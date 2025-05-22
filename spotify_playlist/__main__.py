#!/usr/bin/env python3

"""
Command-line interface (CLI) tool for managing Spotify playlists using the Spotify Web API.
"""

import argparse
import base64
import hashlib  # Added for PKCE
import json
import logging
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests

# --- Constants ---
# IMPORTANT: Replace this with your actual Spotify Application Client ID
# You can get this from the Spotify Developer Dashboard: https://developer.spotify.com/dashboard/
CLIENT_ID = "ef7c1b8bea424297ba96dd0c8f6b4c1f"

# IMPORTANT: Make sure this Redirect URI is added to your Spotify Application's settings
# in the Spotify Developer Dashboard.
REDIRECT_URI = "http://127.0.0.1:8888/callback"  # Ensure port is free

# Determine script directory for storing token and log files
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE_NAME = ".spotify_tokens.json"
TOKEN_FILE_PATH = os.path.join(SCRIPT_DIR, TOKEN_FILE_NAME)

API_BASE_URL = "https://api.spotify.com/v1"
AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"

# Scopes define the permissions your application requests
SCOPES_LIST = [
    "playlist-read-private",
    "playlist-read-collaborative",
    "playlist-modify-public",
    "playlist-modify-private",
    "user-read-private",
    "user-read-email",
]

# --- Global state for the OAuth server ---
AUTH_CODE_GLOBAL = None
AUTH_STATE_RECEIVED_GLOBAL = None
OAUTH_HTTP_SERVER_GLOBAL = None
PKCE_CODE_VERIFIER_GLOBAL = None  # To store code_verifier for token exchange


# --- Token Management ---
def save_tokens(tokens):
    """Saves tokens to the TOKEN_FILE_PATH."""
    try:
        with open(TOKEN_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=4)
        logging.info("Tokens saved to %s", TOKEN_FILE_PATH)
    except IOError as e:
        logging.error("Error saving tokens to %s: %s", TOKEN_FILE_PATH, e)
        print(f"Warning: Could not save tokens: {e}")


def load_tokens():
    """Loads tokens from the TOKEN_FILE_PATH."""
    if not os.path.exists(TOKEN_FILE_PATH):
        logging.debug("Token file %s not found.", TOKEN_FILE_PATH)
        return None
    try:
        with open(TOKEN_FILE_PATH, "r", encoding="utf-8") as f:
            tokens = json.load(f)
            if not all(
                key in tokens for key in ["access_token", "refresh_token", "expires_at"]
            ):
                logging.warning(
                    "Token file %s is malformed or missing essential keys. Discarding.",
                    TOKEN_FILE_PATH,
                )
                clear_tokens()
                return None
            return tokens
    except (IOError, json.JSONDecodeError) as e:
        logging.error("Error loading tokens from %s: %s", TOKEN_FILE_PATH, e)
        print(
            f"Warning: Could not load tokens from {TOKEN_FILE_PATH}. It might be corrupted. Error: {e}"
        )
        clear_tokens()
        return None


def clear_tokens():
    """Removes the token file."""
    if os.path.exists(TOKEN_FILE_PATH):
        try:
            os.remove(TOKEN_FILE_PATH)
            logging.info("Token file %s removed.", TOKEN_FILE_PATH)
        except OSError as e:
            logging.error("Error removing token file %s: %s", TOKEN_FILE_PATH, e)


def refresh_access_token():
    """Refreshes the access token using the stored refresh token (PKCE flow)."""
    logging.info("Attempting to refresh access token using PKCE flow.")
    tokens = load_tokens()
    if not tokens or "refresh_token" not in tokens:
        logging.error("No refresh token found. Please login again.")
        print("No refresh token available. Please use the 'login' command.")
        return False

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": CLIENT_ID,  # Required for PKCE refresh
    }

    try:
        # No Authorization header with client secret for PKCE refresh
        response = requests.post(TOKEN_URL, data=payload, timeout=10)
        response.raise_for_status()

        new_token_data = response.json()
        tokens["access_token"] = new_token_data["access_token"]
        tokens["expires_at"] = time.time() + new_token_data["expires_in"]
        # Spotify might issue a new refresh token, update if provided
        if "refresh_token" in new_token_data:
            tokens["refresh_token"] = new_token_data["refresh_token"]

        save_tokens(tokens)
        logging.info("Access token refreshed (PKCE) and saved successfully.")
        return True

    except requests.exceptions.RequestException as e:
        logging.error("Error refreshing access token (PKCE): %s", e)
        if hasattr(e, "response") and e.response is not None:
            logging.error("Refresh token response content: %s", e.response.text)
            if e.response.status_code in [400, 401]:  # Bad request, invalid grant
                logging.error(
                    "Refresh token is invalid or revoked. Clearing tokens. Please login again."
                )
                clear_tokens()
                print(
                    "Your session has expired or is invalid. Please use the 'login' command."
                )
        return False


def get_access_token():
    """Retrieves a valid access token, refreshing if necessary."""
    tokens = load_tokens()
    if not tokens:
        logging.debug("No tokens found.")
        return None

    if time.time() > tokens.get("expires_at", 0) - 60:
        logging.info("Access token expired or nearing expiration. Attempting refresh.")
        if not refresh_access_token():
            logging.warning("Failed to refresh access token.")
            return None
        tokens = load_tokens()  # Reload after successful refresh

    return tokens.get("access_token") if tokens else None


# --- API Request Helper with Rate Limiting and Token Refresh ---
def make_spotify_request(
    url,
    method="GET",
    headers=None,
    data=None,
    params=None,
    is_retry_after_refresh=False,
):
    """
    Makes a request to the Spotify API, handling rate limits, token refresh, and errors.
    """
    request_headers = headers.copy() if headers else {}

    if (
        TOKEN_URL not in url and AUTH_URL not in url
    ):  # i.e., not an auth-related request itself
        access_token = get_access_token()
        if not access_token:
            logging.error("API request failed: No valid access token. Please login.")
            print("Authentication required. Please use the 'login' command.")
            return None
        request_headers["Authorization"] = f"Bearer {access_token}"

    max_retries = 5
    current_retry = 0
    while current_retry < max_retries:
        try:
            logging.debug(
                "Spotify API Request: %s %s Params: %s Body: %s",
                method,
                url,
                params,
                json.dumps(data) if data else "None",
            )
            response = requests.request(
                method,
                url,
                headers=request_headers,
                json=data,
                params=params,
                timeout=30,
            )
            logging.debug(
                "Spotify API Response Status: %s, Headers: %s",
                response.status_code,
                response.headers,
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", "1"))
                logging.warning(
                    "Rate limit (429) hit. Retrying after %s seconds. Attempt %s/%s",
                    retry_after,
                    current_retry + 1,
                    max_retries,
                )
                time.sleep(retry_after)
                current_retry += 1
                continue

            if response.status_code == 401 and not is_retry_after_refresh:
                logging.warning("Received 401 Unauthorized. Attempting token refresh.")
                if refresh_access_token():
                    logging.info("Token refreshed. Retrying original API request.")
                    refreshed_token_data = load_tokens()
                    if refreshed_token_data and "access_token" in refreshed_token_data:
                        request_headers["Authorization"] = (
                            f"Bearer {refreshed_token_data['access_token']}"
                        )
                        # Retry the same request immediately, once. Mark it as a retry after refresh.
                        return make_spotify_request(
                            url,
                            method,
                            request_headers,
                            data,
                            params,
                            is_retry_after_refresh=True,
                        )
                    else:
                        logging.error(
                            "Failed to load refreshed token. Please login again."
                        )
                        print("Authentication failed. Please use the 'login' command.")
                        return None
                else:
                    logging.error("Token refresh failed after 401. Please login again.")
                    print("Authentication failed. Please use the 'login' command.")
                    return None

            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {"status": "success", "status_code": response.status_code}
            return response.json()

        except requests.exceptions.HTTPError as e:
            logging.error(
                "Spotify API HTTP error: %s - %s for URL %s",
                e.response.status_code,
                e.response.text,
                url,
            )
            error_details = e.response.text
            try:
                error_json = e.response.json()
                error_message = error_json.get("error", {}).get(
                    "message", e.response.text
                )
                error_details = f"{error_message} (Status: {e.response.status_code})"
            except json.JSONDecodeError:
                pass
            print(f"API Error: {error_details}")
            if e.response.status_code == 403:
                print(
                    "This might be due to insufficient permissions (scopes) for your token."
                )
            return None
        except requests.exceptions.RequestException as e:
            logging.error(
                "Spotify API Request failed: %s. Attempt %s/%s",
                e,
                current_retry + 1,
                max_retries,
            )
            if current_retry < max_retries - 1:
                time.sleep(1 + (2**current_retry))
            current_retry += 1
    logging.error(
        "Max retries reached for %s %s. Request failed permanently.", method, url
    )
    print(
        f"Request to Spotify API ({url}) failed after multiple retries. Check logs for details."
    )
    return None


# --- HTTP Server for OAuth Callback ---
class _CallbackHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, original_csrf_state):
        self.original_csrf_state = original_csrf_state
        super().__init__(request, client_address, server)

    def do_GET(self):
        global AUTH_CODE_GLOBAL, AUTH_STATE_RECEIVED_GLOBAL, OAUTH_HTTP_SERVER_GLOBAL
        query_params = parse_qs(urlparse(self.path).query)
        code = query_params.get("code", [None])[0]
        state = query_params.get("state", [None])[0]
        AUTH_STATE_RECEIVED_GLOBAL = state

        if state is None or state != self.original_csrf_state:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Error: State mismatch.</h1></body></html>"
            )
            logging.error(
                "OAuth callback state mismatch. Expected: %s, Got: %s",
                self.original_csrf_state,
                state,
            )
            AUTH_CODE_GLOBAL = "error_csrf_state_mismatch"
        elif code:
            AUTH_CODE_GLOBAL = code
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Auth successful! Close window.</h1></body></html>"
            )
            logging.info("OAuth authorization code received.")
        else:
            error = query_params.get("error", ["Unknown OAuth error"])[0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<html><body><h1>Auth Failed: {error}</h1></body></html>".encode(
                    "utf-8"
                )
            )
            logging.error("OAuth error from Spotify callback: %s", error)
            AUTH_CODE_GLOBAL = f"error_oauth_{error}"

        if OAUTH_HTTP_SERVER_GLOBAL:
            threading.Thread(
                target=OAUTH_HTTP_SERVER_GLOBAL.shutdown, daemon=True
            ).start()


def _start_oauth_callback_server(csrf_state):
    global OAUTH_HTTP_SERVER_GLOBAL
    parsed_redirect_uri = urlparse(REDIRECT_URI)
    server_address = (parsed_redirect_uri.hostname, parsed_redirect_uri.port)

    def handler_factory(*args, **kwargs):
        return _CallbackHandler(*args, original_csrf_state=csrf_state, **kwargs)

    try:
        OAUTH_HTTP_SERVER_GLOBAL = HTTPServer(server_address, handler_factory)
    except OSError as e:
        logging.error("Could not start OAuth server on %s: %s", server_address, e)
        print(f"Error: Port {parsed_redirect_uri.port} might be in use.")
        return None
    logging.info(
        "Starting OAuth server on %s://%s:%s%s",
        parsed_redirect_uri.scheme,
        parsed_redirect_uri.hostname,
        parsed_redirect_uri.port,
        parsed_redirect_uri.path,
    )
    server_thread = threading.Thread(
        target=OAUTH_HTTP_SERVER_GLOBAL.serve_forever, daemon=True
    )
    server_thread.start()
    logging.info("OAuth server started.")
    return server_thread


# --- Spotify API Helper Functions ---
def get_current_user_id(access_token_override=None):
    """Fetches the current user's Spotify ID. Can use an override token or get one."""
    tokens = load_tokens()
    if tokens and "user_id" in tokens:
        logging.debug("Using stored user ID: %s", tokens["user_id"])
        return tokens["user_id"]
    logging.info("Fetching current user's profile to get user ID.")
    headers = {}
    if access_token_override:
        headers["Authorization"] = f"Bearer {access_token_override}"
    response_json = make_spotify_request(f"{API_BASE_URL}/me", headers=headers)
    if response_json and "id" in response_json:
        user_id = response_json["id"]
        logging.info("Fetched user ID: %s", user_id)
        if tokens:  # tokens might be None if get_access_token failed
            tokens["user_id"] = user_id
            save_tokens(tokens)
        return user_id
    logging.error("Could not fetch user ID from /me endpoint.")
    return None


def get_playlist_track_uris(playlist_id):
    """Fetches all track URIs from a given playlist."""
    logging.info("Fetching all track URIs for playlist ID: %s", playlist_id)
    track_uris = set()
    limit = 50
    offset = 0
    while True:
        fields = "items(track(uri)),next"
        params = {"limit": limit, "offset": offset, "fields": fields}
        logging.debug("Fetching track URIs page for %s: offset=%s", playlist_id, offset)
        response_json = make_spotify_request(
            f"{API_BASE_URL}/playlists/{playlist_id}/tracks", params=params
        )
        if not response_json or "items" not in response_json:
            logging.warning("Failed to fetch track URIs for %s.", playlist_id)
            return None
        for item in response_json.get("items", []):
            if item.get("track") and item["track"].get("uri"):
                track_uris.add(item["track"]["uri"])
        if response_json.get("next"):
            offset += limit
            time.sleep(0.05)
        else:
            break
    logging.info(
        "Found %s unique track URIs in playlist %s.", len(track_uris), playlist_id
    )
    return track_uris


# --- Command Handler Functions ---
def handle_login(args):
    """Handles the 'login' command to authenticate with Spotify."""
    global AUTH_CODE_GLOBAL, AUTH_STATE_RECEIVED_GLOBAL, OAUTH_HTTP_SERVER_GLOBAL, PKCE_CODE_VERIFIER_GLOBAL

    if CLIENT_ID == "YOUR_CLIENT_ID":
        print(
            "CRITICAL: CLIENT_ID is not set. Edit the script to add your Spotify API Client ID."
        )
        logging.critical("Login attempt with placeholder CLIENT_ID.")
        return

    csrf_state = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8").rstrip("=")
    logging.debug("Generated CSRF state: %s", csrf_state)

    # PKCE: Generate code verifier and challenge
    PKCE_CODE_VERIFIER_GLOBAL = (
        base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    )
    logging.debug("PKCE code_verifier (first 10): %s", PKCE_CODE_VERIFIER_GLOBAL[:10])
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(PKCE_CODE_VERIFIER_GLOBAL.encode("utf-8")).digest()
        )
        .decode("utf-8")
        .rstrip("=")
    )
    logging.debug("PKCE code_challenge (first 10): %s", code_challenge[:10])

    AUTH_CODE_GLOBAL = None
    AUTH_STATE_RECEIVED_GLOBAL = None
    server_thread = _start_oauth_callback_server(csrf_state)
    if not server_thread:
        return

    auth_params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES_LIST),
        "state": csrf_state,
        "code_challenge_method": "S256",  # PKCE parameter
        "code_challenge": code_challenge,  # PKCE parameter
    }
    authorization_url = f"{AUTH_URL}?{urlencode(auth_params)}"
    print(
        f"\nPlease open this URL in your browser to authorize:\n{authorization_url}\nWaiting..."
    )
    try:
        webbrowser.open(authorization_url)
        logging.info("Opened browser for Spotify authorization.")
    except Exception as e:
        logging.warning("Could not open browser: %s. Open URL manually.", e)

    server_thread.join(timeout=180)  # Wait for callback
    if OAUTH_HTTP_SERVER_GLOBAL:
        OAUTH_HTTP_SERVER_GLOBAL.server_close()
        OAUTH_HTTP_SERVER_GLOBAL = None

    if AUTH_CODE_GLOBAL is None:
        logging.error("Login timeout or callback server error.")
        print("Login timed out/cancelled.")
        return
    if AUTH_CODE_GLOBAL.startswith("error_"):
        logging.error("Login failed: %s", AUTH_CODE_GLOBAL)
        print(
            f"Login failed: {AUTH_CODE_GLOBAL.replace('error_', '').replace('_', ' ')}. Try again."
        )
        return
    logging.info("Auth code obtained (first 20): %s...", AUTH_CODE_GLOBAL[:20])

    # Exchange auth code for token using PKCE
    token_payload = {
        "grant_type": "authorization_code",
        "code": AUTH_CODE_GLOBAL,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": PKCE_CODE_VERIFIER_GLOBAL,  # Send the verifier
    }
    try:
        logging.info("Exchanging auth code for token (PKCE).")
        # No Authorization header with client secret for PKCE
        response = requests.post(TOKEN_URL, data=token_payload, timeout=15)
        response.raise_for_status()
        token_data = response.json()
        token_data["expires_at"] = time.time() + token_data["expires_in"]

        # Fetch user ID and store it with tokens
        user_id = get_current_user_id(access_token_override=token_data["access_token"])
        if user_id:
            token_data["user_id"] = user_id
        else:
            logging.warning("Could not fetch user_id immediately after login.")

        save_tokens(token_data)
        print("Login successful! Tokens stored.")
        logging.info("Tokens obtained (PKCE) and stored.")
    except requests.exceptions.RequestException as e:
        logging.error("Error exchanging code for token (PKCE): %s", e)
        if hasattr(e, "response") and e.response is not None:
            logging.error("Token exchange response: %s", e.response.text)
            try:
                error_info = e.response.json()
                print(
                    f"Token exchange failed: {error_info.get('error_description', e.response.text)}"
                )
            except json.JSONDecodeError:
                print(f"Token exchange failed. Server response: {e.response.text}")
        else:
            print(f"Token exchange failed due to a network error: {e}")


def handle_list_playlists(args):
    """Handles the 'list' command to display user's playlists."""
    logging.info("Executing 'list playlists' command.")
    all_playlists = []
    limit = 50
    offset = 0
    while True:
        params = {
            "limit": limit,
            "offset": offset,
            "fields": "items(id,name,tracks(total)),next",
        }
        logging.debug("Fetching playlists page: offset=%s", offset)
        response = make_spotify_request(f"{API_BASE_URL}/me/playlists", params=params)
        if not response or "items" not in response:
            logging.warning("Failed to fetch playlists or malformed response.")
            return
        all_playlists.extend(response.get("items", []))
        if response.get("next"):
            offset += limit
            time.sleep(0.05)
        else:
            break
    if not all_playlists:
        print("No playlists found.")
    else:
        print(f"\nYour Playlists ({len(all_playlists)} total):")
        for item in all_playlists:
            print(
                f"  ID: {item['id']}\n  Name: {item['name']}\n  Tracks: {item.get('tracks',{}).get('total','N/A')}\n{'-'*20}"
            )
    logging.info("Displayed %s playlists.", len(all_playlists))


def handle_get_tracks(args):
    """Handles the 'get-tracks' command for a specific playlist."""
    playlist_id = args.playlist_id
    logging.info("Executing 'get-tracks' for playlist ID: %s", playlist_id)
    playlist_info = make_spotify_request(
        f"{API_BASE_URL}/playlists/{playlist_id}",
        params={"fields": "name,tracks(total)"},
    )
    if not playlist_info:
        print(f"Could not get info for playlist {playlist_id}.")
        return

    name = playlist_info.get("name", "?")
    total = playlist_info.get("tracks", {}).get("total", "?")
    print(f"\nTracks for '{name}' (ID: {playlist_id}, Total: {total}):")

    all_tracks = []
    limit = 50
    offset = 0
    while True:
        fields = "items(track(name,album(name),artists(name),uri,is_local)),next"
        params = {"limit": limit, "offset": offset, "fields": fields}
        logging.debug("Fetching tracks page for %s: offset=%s", playlist_id, offset)
        response = make_spotify_request(
            f"{API_BASE_URL}/playlists/{playlist_id}/tracks", params=params
        )
        if not response or "items" not in response:
            logging.warning("Failed to fetch tracks for %s.", playlist_id)
            return
        for item in response.get("items", []):
            t = item.get("track")
            if t:
                if t.get("is_local", False):
                    all_tracks.append(f"[Local] - {t.get('name','?')}")
                else:
                    artists = ", ".join(
                        [a.get("name", "?") for a in t.get("artists", [])]
                    )
                    all_tracks.append(
                        f"{artists} - {t.get('album',{}).get('name','?')} - {t.get('name','?')}"
                    )
            else:
                all_tracks.append("[Unavailable Track]")
        if response.get("next"):
            offset += limit
            time.sleep(0.05)
        else:
            break
    if not all_tracks:
        print("No tracks found or playlist is empty.")
    else:
        for track_line in all_tracks:
            print(f"  - {track_line}")
    logging.info("Displayed %s tracks for playlist %s.", len(all_tracks), playlist_id)


def handle_create_playlist(args):
    """Handles the 'create' command to make a new playlist."""
    name = args.name
    desc = args.description or ""
    public = not args.private
    collab = args.collaborative
    logging.info(
        "Create playlist: Name='%s', Public=%s, Collab=%s", name, public, collab
    )
    user_id = get_current_user_id()
    if not user_id:
        print("Error: Could not get User ID. Login again.")
        logging.error("Create failed: no User ID.")
        return
    if collab and public:
        logging.warning("Collab playlists must be private.")
        print("Note: Collab playlists are set to private.")
        public = False

    payload = {
        "name": name,
        "public": public,
        "collaborative": collab,
        "description": desc,
    }
    logging.debug("Creating playlist with payload: %s", payload)
    response = make_spotify_request(
        f"{API_BASE_URL}/users/{user_id}/playlists", method="POST", data=payload
    )
    if response and "id" in response:
        p_name = response.get("name", name)
        p_id = response["id"]
        link = response.get("external_urls", {}).get("spotify", "N/A")
        print(f"Playlist '{p_name}' created!\n  ID: {p_id}\n  Link: {link}")
        logging.info("Playlist '%s' (ID: %s) created.", p_name, p_id)
    else:
        logging.error("Failed to create playlist '%s'. Response: %s", name, response)


def handle_add_track(args):
    """Handles the 'add-track' command to search and add a track, preventing duplicates."""
    p_id = args.playlist_id
    query = args.query
    logging.info("Add track: PlaylistID='%s', Query='%s'", p_id, query)

    search_params = {"q": query, "type": "track", "limit": 1}
    logging.debug("Searching for track: '%s'", query)
    s_response = make_spotify_request(f"{API_BASE_URL}/search", params=search_params)
    if (
        not s_response
        or not s_response.get("tracks")
        or not s_response["tracks"].get("items")
    ):
        print(f"Error: Track search for '{query}' failed or no results.")
        logging.error("Search '%s' no results: %s", query, s_response)
        return

    track = s_response["tracks"]["items"][0]
    uri = track["uri"]
    name = track["name"]
    artists = ", ".join([a["name"] for a in track.get("artists", [])])
    logging.info("Found: '%s' by %s (URI: %s)", name, artists, uri)
    print(f"Found: '{name}' by {artists}.")

    logging.info("Checking for duplicate URI %s in playlist %s.", uri, p_id)
    existing_uris = get_playlist_track_uris(p_id)
    if existing_uris is None:
        print(f"Could not verify existing tracks in {p_id}. Aborting.")
        return
    if uri in existing_uris:
        print(f"Track '{name}' by {artists} already in playlist {p_id}.")
        logging.info("Track %s already in %s.", uri, p_id)
        return

    add_payload = {"uris": [uri]}
    logging.debug("Adding URI %s to playlist %s", uri, p_id)
    response = make_spotify_request(
        f"{API_BASE_URL}/playlists/{p_id}/tracks", method="POST", data=add_payload
    )
    if response and (response.get("snapshot_id") or response.get("status_code") == 201):
        print(f"Track '{name}' added to playlist {p_id}.")
        logging.info(
            "Track '%s' added. Snapshot: %s", uri, response.get("snapshot_id", "N/A")
        )
    else:
        logging.error(
            "Failed to add track '%s' to %s. Response: %s", name, p_id, response
        )


# --- Main Execution ---
def main():
    """Main function to parse arguments and dispatch commands."""
    parser = argparse.ArgumentParser(
        description="Manage Spotify playlists via CLI.",
        epilog="Run 'login' first. Ensure CLIENT_ID is set in script.",
    )
    parser.add_argument(
        "--loglevel",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level.",
    )

    subs = parser.add_subparsers(title="commands", dest="command", required=True)
    subs.add_parser("login", help="Authenticate with Spotify.").set_defaults(
        func=handle_login
    )
    subs.add_parser("list", help="List your playlists.").set_defaults(
        func=handle_list_playlists
    )
    p_get = subs.add_parser("get-tracks", help="List tracks for a playlist.")
    p_get.add_argument("playlist_id", help="Playlist ID.")
    p_get.set_defaults(func=handle_get_tracks)
    p_create = subs.add_parser("create", help="Create a playlist.")
    p_create.add_argument("name", help="Playlist name.")
    p_create.add_argument("--description", default="", help="Description.")
    p_create.add_argument("--private", action="store_true", help="Make private.")
    p_create.add_argument(
        "--collaborative",
        action="store_true",
        help="Make collaborative (implies private).",
    )
    p_create.set_defaults(func=handle_create_playlist)
    p_add = subs.add_parser("add-track", help="Search and add track to playlist.")
    p_add.add_argument("playlist_id", help="Playlist ID to add to.")
    p_add.add_argument("query", help="Track search query.")
    p_add.set_defaults(func=handle_add_track)

    args = parser.parse_args()

    log_file_path = os.path.join(SCRIPT_DIR, "spotify_playlist.log")
    logging.basicConfig(
        level=getattr(logging, args.loglevel.upper()),
        format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(module)s.%(funcName)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    logging.info("App started. Command: %s, LogLevel: %s", args.command, args.loglevel)
    if CLIENT_ID == "YOUR_CLIENT_ID":
        logging.warning("CLIENT_ID is a placeholder. Login will likely fail.")
        if args.command != "login":
            print(
                "Warning: CLIENT_ID not configured. Edit script. Operations may fail."
            )

    if hasattr(args, "func"):
        try:
            args.func(args)
        except Exception as e:
            logging.critical(
                "Unhandled exception in '%s': %s", args.command, e, exc_info=True
            )
            print(f"Unexpected error: {e}. Check '{log_file_path}' for details.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
