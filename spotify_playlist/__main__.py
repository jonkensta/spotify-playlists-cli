#!/usr/bin/env python3

"""
Command-line interface (CLI) tool for managing Spotify playlists using the Spotify Web API.
"""

import argparse
import base64
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
# IMPORTANT: Replace these with your actual Spotify Application credentials
# You can get these from the Spotify Developer Dashboard: https://developer.spotify.com/dashboard/
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"

# IMPORTANT: Make sure this Redirect URI is added to your Spotify Application's settings
# in the Spotify Developer Dashboard.
REDIRECT_URI = "http://127.0.0.1:8888/callback"  # Ensure port is free

TOKEN_FILE = ".spotify_tokens.json"  # Stores tokens in the current directory
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
# These are used by the HTTP server to communicate back to the main thread during login
AUTH_CODE_GLOBAL = None
AUTH_STATE_RECEIVED_GLOBAL = None
OAUTH_HTTP_SERVER_GLOBAL = None  # Holds the HTTPServer instance

# --- Logging Setup ---
# Configured in main() based on command-line arguments


# --- Token Management ---
def save_tokens(tokens):
    """Saves tokens to the TOKEN_FILE."""
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=4)
        logging.info("Tokens saved to %s", TOKEN_FILE)
    except IOError as e:
        logging.error("Error saving tokens to %s: %s", TOKEN_FILE, e)
        print(f"Warning: Could not save tokens: {e}")


def load_tokens():
    """Loads tokens from the TOKEN_FILE."""
    if not os.path.exists(TOKEN_FILE):
        logging.debug("Token file %s not found.", TOKEN_FILE)
        return None
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            tokens = json.load(f)
            # Basic validation
            if not all(
                key in tokens for key in ["access_token", "refresh_token", "expires_at"]
            ):
                logging.warning(
                    "Token file %s is malformed or missing essential keys. Discarding.",
                    TOKEN_FILE,
                )
                clear_tokens()  # Remove malformed file
                return None
            return tokens
    except (IOError, json.JSONDecodeError) as e:
        logging.error("Error loading tokens from %s: %s", TOKEN_FILE, e)
        print(
            f"Warning: Could not load tokens from {TOKEN_FILE}. It might be corrupted. Error: {e}"
        )
        clear_tokens()
        return None


def clear_tokens():
    """Removes the token file."""
    if os.path.exists(TOKEN_FILE):
        try:
            os.remove(TOKEN_FILE)
            logging.info("Token file %s removed.", TOKEN_FILE)
        except OSError as e:
            logging.error("Error removing token file %s: %s", TOKEN_FILE, e)


def refresh_access_token():
    """Refreshes the access token using the stored refresh token."""
    logging.info("Attempting to refresh access token.")
    tokens = load_tokens()
    if not tokens or "refresh_token" not in tokens:
        logging.error(
            "No refresh token found. Please login again using the 'login' command."
        )
        print("No refresh token available. Please use the 'login' command.")
        return False

    payload = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}

    auth_string = f"{CLIENT_ID}:{CLIENT_SECRET}"
    b64_auth_string = base64.b64encode(auth_string.encode()).decode()
    headers = {
        "Authorization": f"Basic {b64_auth_string}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        response = requests.post(TOKEN_URL, data=payload, headers=headers, timeout=10)
        response.raise_for_status()

        new_token_data = response.json()
        tokens["access_token"] = new_token_data["access_token"]
        tokens["expires_at"] = time.time() + new_token_data["expires_in"]
        if "refresh_token" in new_token_data:
            tokens["refresh_token"] = new_token_data["refresh_token"]

        save_tokens(tokens)
        logging.info("Access token refreshed and saved successfully.")
        return True

    except requests.exceptions.RequestException as e:
        logging.error("Error refreshing access token: %s", e)
        if hasattr(e, "response") and e.response is not None:
            logging.error("Refresh token response content: %s", e.response.text)
            if e.response.status_code in [400, 401]:
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
        tokens = load_tokens()

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

    if TOKEN_URL not in url and AUTH_URL not in url:
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
                logging.warning(
                    "Received 401 Unauthorized. Attempting token refresh for API request."
                )
                if refresh_access_token():
                    logging.info("Token refreshed. Retrying original API request.")
                    refreshed_token = load_tokens()["access_token"]
                    request_headers["Authorization"] = f"Bearer {refreshed_token}"
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
                        "Token refresh failed after 401 during API request. Please login again."
                    )
                    print(
                        "Authentication failed (token might be expired or invalid). Please use the 'login' command."
                    )
                    return None

            response.raise_for_status()

            if (
                response.status_code == 204 or not response.content
            ):  # Handle 204 No Content or empty responses
                return {
                    "status": "success",
                    "status_code": response.status_code,
                }  # Indicate success
            return response.json()

        except requests.exceptions.HTTPError as e:
            logging.error(
                "Spotify API HTTP error: %s - %s for URL %s",
                e.response.status_code,
                e.response.text,
                url,
            )
            error_details = e.response.text
            try:  # Try to parse JSON error from Spotify
                error_json = e.response.json()
                error_message = error_json.get("error", {}).get(
                    "message", e.response.text
                )
                error_details = f"{error_message} (Status: {e.response.status_code})"
            except json.JSONDecodeError:
                pass  # Use raw text if not JSON

            print(f"API Error: {error_details}")
            if e.response.status_code == 403:
                print(
                    "This might be due to insufficient permissions (scopes) for your token."
                )
            return None
        except (
            requests.exceptions.RequestException
        ) as e:  # Other errors (timeout, connection error)
            logging.error(
                "Spotify API Request failed: %s. Attempt %s/%s",
                e,
                current_retry + 1,
                max_retries,
            )
            if current_retry < max_retries - 1:
                time.sleep(
                    1 + (2**current_retry)
                )  # Exponential backoff for network issues
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
                b"<html><body><h1>Error: State mismatch (CSRF protection).</h1><p>Please try logging in again.</p></body></html>"
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
                b"<html><body><h1>Authentication successful!</h1><p>You can close this browser window and return to the terminal.</p></body></html>"
            )
            logging.info("OAuth authorization code received successfully via callback.")
        else:
            error = query_params.get("error", ["Unknown OAuth error"])[0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<html><body><h1>Authentication Failed</h1><p>Error: {error}. Please try again.</p></body></html>".encode(
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
        logging.error(
            "Could not start OAuth callback server on %s: %s", server_address, e
        )
        print(
            f"Error: Could not start callback server on {parsed_redirect_uri.hostname}:{parsed_redirect_uri.port}. Port might be in use."
        )
        return None

    logging.info(
        "Starting OAuth callback server on %s://%s:%s%s",
        parsed_redirect_uri.scheme,
        parsed_redirect_uri.hostname,
        parsed_redirect_uri.port,
        parsed_redirect_uri.path,
    )

    server_thread = threading.Thread(
        target=OAUTH_HTTP_SERVER_GLOBAL.serve_forever, daemon=True
    )
    server_thread.start()
    logging.info("OAuth callback server started and listening.")
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
        if tokens:
            tokens["user_id"] = user_id
            save_tokens(tokens)
        return user_id
    else:
        logging.error("Could not fetch user ID from /me endpoint.")
        return None


def get_playlist_track_uris(playlist_id):
    """Fetches all track URIs from a given playlist."""
    logging.info("Fetching all track URIs for playlist ID: %s", playlist_id)
    track_uris = set()
    limit = 50
    offset = 0

    while True:
        # Request only the track URI and if there's a next page
        fields = "items(track(uri)),next"
        params = {"limit": limit, "offset": offset, "fields": fields}
        logging.debug(
            "Fetching track URIs for playlist %s: offset=%s, limit=%s",
            playlist_id,
            offset,
            limit,
        )

        response_json = make_spotify_request(
            f"{API_BASE_URL}/playlists/{playlist_id}/tracks", params=params
        )

        if not response_json or "items" not in response_json:
            logging.warning(
                "Failed to fetch track URIs for playlist %s or malformed response.",
                playlist_id,
            )
            return None  # Indicate error

        for item in response_json.get("items", []):
            track_data = item.get("track")
            if track_data and track_data.get("uri"):  # Ensure track and URI exist
                track_uris.add(track_data["uri"])

        if response_json.get("next"):
            offset += limit
            time.sleep(0.05)  # Small polite delay
        else:
            break  # No more pages

    logging.info(
        "Found %s unique track URIs in playlist %s.", len(track_uris), playlist_id
    )
    return track_uris


# --- Command Handler Functions ---
def handle_login(args):
    """Handles the 'login' command to authenticate with Spotify."""
    global AUTH_CODE_GLOBAL, AUTH_STATE_RECEIVED_GLOBAL, OAUTH_HTTP_SERVER_GLOBAL

    if CLIENT_ID == "YOUR_CLIENT_ID" or CLIENT_SECRET == "YOUR_CLIENT_SECRET":
        print("CRITICAL: CLIENT_ID or CLIENT_SECRET is not set in the script.")
        print(
            "Please edit the script (spotify_playlist.py) near the top to add your Spotify API credentials."
        )
        print(
            "You can obtain these from the Spotify Developer Dashboard: https://developer.spotify.com/dashboard/"
        )
        logging.critical("Login attempt with placeholder CLIENT_ID/CLIENT_SECRET.")
        return

    csrf_state = base64.urlsafe_b64encode(os.urandom(16)).decode()
    logging.debug("Generated CSRF state for login: %s", csrf_state)

    AUTH_CODE_GLOBAL = None
    AUTH_STATE_RECEIVED_GLOBAL = None
    server_thread = _start_oauth_callback_server(csrf_state)
    if not server_thread:
        return

    auth_params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(
            SCOPES_LIST
        ),  # Join the list of scopes into a space-separated string
        "state": csrf_state,
    }
    authorization_url = f"{AUTH_URL}?{urlencode(auth_params)}"

    print(
        "\nTo authorize this application, please open the following URL in your web browser:"
    )
    print(authorization_url)
    print("\nWaiting for authorization...")

    try:
        webbrowser.open(authorization_url)
        logging.info("Opened browser for Spotify authorization.")
    except Exception as e:
        logging.warning(
            "Could not open browser automatically: %s. Please open the URL manually.", e
        )

    server_thread.join(timeout=180)

    if OAUTH_HTTP_SERVER_GLOBAL:
        OAUTH_HTTP_SERVER_GLOBAL.server_close()
        OAUTH_HTTP_SERVER_GLOBAL = None

    if AUTH_CODE_GLOBAL is None:
        logging.error(
            "Login timeout or callback server failed to receive authorization code."
        )
        print("Login timed out or was cancelled.")
        return

    if AUTH_CODE_GLOBAL.startswith("error_csrf_"):
        logging.error("Login failed due to CSRF state mismatch: %s", AUTH_CODE_GLOBAL)
        print(
            f"Login failed: {AUTH_CODE_GLOBAL.replace('error_csrf_', '').replace('_', ' ')}. Please try again."
        )
        return
    if AUTH_CODE_GLOBAL.startswith("error_oauth_"):
        logging.error(
            "Login failed due to OAuth error from Spotify: %s", AUTH_CODE_GLOBAL
        )
        print(
            f"Login failed: Spotify reported an error ({AUTH_CODE_GLOBAL.replace('error_oauth_', '')}). Please try again."
        )
        return

    logging.info("Authorization code obtained: %s...", AUTH_CODE_GLOBAL[:20])

    token_payload = {
        "grant_type": "authorization_code",
        "code": AUTH_CODE_GLOBAL,
        "redirect_uri": REDIRECT_URI,
    }

    client_credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    auth_header_value = base64.b64encode(client_credentials.encode()).decode()
    token_headers = {
        "Authorization": f"Basic {auth_header_value}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        logging.info("Exchanging authorization code for tokens.")
        response = requests.post(
            TOKEN_URL, data=token_payload, headers=token_headers, timeout=15
        )
        response.raise_for_status()

        token_data = response.json()
        token_data["expires_at"] = time.time() + token_data["expires_in"]

        user_id = get_current_user_id(access_token_override=token_data["access_token"])
        if user_id:
            token_data["user_id"] = user_id
        else:
            logging.warning(
                "Could not fetch user_id immediately after login, but tokens are stored."
            )

        save_tokens(token_data)
        print("Login successful! Tokens have been stored.")
        logging.info("Tokens successfully obtained and stored.")

    except requests.exceptions.RequestException as e:
        logging.error("Error exchanging code for token: %s", e)
        if hasattr(e, "response") and e.response is not None:
            logging.error("Token exchange response content: %s", e.response.text)
            try:
                error_info = e.response.json()
                print(
                    f"Failed to obtain access token: {error_info.get('error_description', e.response.text)}"
                )
            except json.JSONDecodeError:
                print(
                    f"Failed to obtain access token. Server response: {e.response.text}"
                )
        else:
            print(
                f"Failed to obtain access token due to a network or request error: {e}"
            )


def handle_list_playlists(args):
    """Handles the 'list' command to display user's playlists."""
    logging.info("Executing 'list playlists' command.")
    all_playlists_data = []
    limit = 50
    offset = 0

    while True:
        params = {
            "limit": limit,
            "offset": offset,
            "fields": "items(id,name,tracks(total)),next,total",
        }
        logging.debug("Fetching playlists: offset=%s, limit=%s", offset, limit)

        response_json = make_spotify_request(
            f"{API_BASE_URL}/me/playlists", params=params
        )

        if not response_json or "items" not in response_json:
            logging.warning("Failed to fetch playlists or response was malformed.")
            return

        all_playlists_data.extend(response_json.get("items", []))

        if response_json.get("next"):
            offset += limit
            time.sleep(0.05)
        else:
            break

    if not all_playlists_data:
        print("No playlists found for your account.")
    else:
        print(f"\nYour Playlists ({len(all_playlists_data)} total):")
        for item in all_playlists_data:
            print(f"  ID: {item['id']}")
            print(f"  Name: {item['name']}")
            print(f"  Tracks: {item.get('tracks', {}).get('total', 'N/A')}")
            print("-" * 20)
    logging.info("Displayed %s playlists.", len(all_playlists_data))


def handle_get_tracks(args):
    """Handles the 'get-tracks' command for a specific playlist."""
    playlist_id = args.playlist_id
    logging.info("Executing 'get-tracks' for playlist ID: %s", playlist_id)

    all_tracks_formatted = []
    limit = 50
    offset = 0

    playlist_info = make_spotify_request(
        f"{API_BASE_URL}/playlists/{playlist_id}",
        params={"fields": "name,tracks(total)"},
    )
    if not playlist_info:
        print(f"Could not retrieve information for playlist ID: {playlist_id}")
        return

    playlist_name = playlist_info.get("name", "Unknown Playlist")
    total_tracks_expected = playlist_info.get("tracks", {}).get("total", "N/A")
    print(
        f"\nTracks for Playlist: '{playlist_name}' (ID: {playlist_id}, Total: {total_tracks_expected}):"
    )

    while True:
        fields = "items(track(name,album(name),artists(name),uri,is_local)),next"
        params = {"limit": limit, "offset": offset, "fields": fields}
        logging.debug(
            "Fetching tracks for playlist %s: offset=%s, limit=%s",
            playlist_id,
            offset,
            limit,
        )

        response_json = make_spotify_request(
            f"{API_BASE_URL}/playlists/{playlist_id}/tracks", params=params
        )

        if not response_json or "items" not in response_json:
            logging.warning(
                "Failed to fetch tracks for playlist %s or malformed response.",
                playlist_id,
            )
            return

        for item in response_json.get("items", []):
            track_data = item.get("track")
            if track_data:
                if track_data.get("is_local", False):
                    all_tracks_formatted.append(
                        f"[Local Track] - {track_data.get('name', 'Unknown Track')}"
                    )
                else:
                    track_name = track_data.get("name", "Unknown Track")
                    album_name = track_data.get("album", {}).get(
                        "name", "Unknown Album"
                    )
                    artist_names = ", ".join(
                        [
                            artist.get("name", "Unknown Artist")
                            for artist in track_data.get("artists", [])
                        ]
                    )
                    all_tracks_formatted.append(
                        f"{artist_names} - {album_name} - {track_name}"
                    )
            else:
                all_tracks_formatted.append("[Unavailable Track]")

        if response_json.get("next"):
            offset += limit
            time.sleep(0.05)
        else:
            break

    if not all_tracks_formatted:
        print(f"No tracks found in playlist '{playlist_name}' or it might be empty.")
    else:
        for track_line in all_tracks_formatted:
            print(f"  - {track_line}")
    logging.info(
        "Displayed %s tracks for playlist %s.", len(all_tracks_formatted), playlist_id
    )


def handle_create_playlist(args):
    """Handles the 'create' command to make a new playlist."""
    playlist_name = args.name
    description = args.description or ""
    public_playlist = not args.private
    collaborative_playlist = args.collaborative

    logging.info(
        "Executing 'create playlist': Name='%s', Public=%s, Collab=%s",
        playlist_name,
        public_playlist,
        collaborative_playlist,
    )

    user_id = get_current_user_id()
    if not user_id:
        print(
            "Error: Could not determine your User ID. Please try logging in again or ensure you are logged in."
        )
        logging.error("Create playlist failed: User ID could not be fetched/found.")
        return

    if collaborative_playlist and public_playlist:
        logging.warning(
            "Collaborative playlists must be private. Setting playlist to private for creation."
        )
        print(
            "Note: Collaborative playlists are automatically set to private by Spotify."
        )
        public_playlist = False

    create_url = f"{API_BASE_URL}/users/{user_id}/playlists"
    payload = {
        "name": playlist_name,
        "public": public_playlist,
        "collaborative": collaborative_playlist,
        "description": description,
    }

    logging.debug("Creating playlist with payload: %s", payload)
    response_json = make_spotify_request(create_url, method="POST", data=payload)

    if response_json and "id" in response_json:
        created_playlist_name = response_json.get("name", playlist_name)
        created_playlist_id = response_json["id"]
        print(f"Playlist '{created_playlist_name}' created successfully!")
        print(f"  ID: {created_playlist_id}")
        print(f"  Link: {response_json.get('external_urls', {}).get('spotify', 'N/A')}")
        logging.info(
            "Playlist '%s' (ID: %s) created.",
            created_playlist_name,
            created_playlist_id,
        )
    else:
        logging.error(
            "Failed to create playlist '%s'. Response: %s", playlist_name, response_json
        )


def handle_add_track(args):
    """Handles the 'add-track' command to search and add a track, preventing duplicates."""
    playlist_id = args.playlist_id
    search_query = args.query
    logging.info(
        "Executing 'add-track': PlaylistID='%s', Query='%s'", playlist_id, search_query
    )

    # 1. Search for the track
    search_params = {"q": search_query, "type": "track", "limit": 1}
    logging.debug("Searching for track with query: '%s'", search_query)
    search_response_json = make_spotify_request(
        f"{API_BASE_URL}/search", params=search_params
    )

    if (
        not search_response_json
        or not search_response_json.get("tracks")
        or not search_response_json["tracks"].get("items")
    ):
        print(f"Error: Track search for '{search_query}' failed or found no results.")
        logging.error(
            "Search for '%s' yielded no results or bad response: %s",
            search_query,
            search_response_json,
        )
        return

    found_track = search_response_json["tracks"]["items"][0]
    track_uri = found_track["uri"]
    track_name = found_track["name"]
    artist_names = ", ".join(
        [artist["name"] for artist in found_track.get("artists", [])]
    )

    logging.info(
        "Found track: '%s' by %s (URI: %s)", track_name, artist_names, track_uri
    )
    print(f"Found track: '{track_name}' by {artist_names}.")

    # 2. Check if track already exists in the playlist
    logging.info(
        "Checking for duplicate track URI %s in playlist %s.", track_uri, playlist_id
    )
    existing_track_uris = get_playlist_track_uris(playlist_id)

    if existing_track_uris is None:
        # Error occurred while fetching existing tracks, get_playlist_track_uris would have logged it.
        print(
            f"Could not verify existing tracks in playlist {playlist_id}. Aborting add operation."
        )
        return

    if track_uri in existing_track_uris:
        print(
            f"Track '{track_name}' by {artist_names} (URI: {track_uri}) is already in playlist {playlist_id}."
        )
        logging.info(
            "Track %s already exists in playlist %s. Skipping add.",
            track_uri,
            playlist_id,
        )
        return

    # 3. Add the track to the specified playlist if not a duplicate
    add_track_url = f"{API_BASE_URL}/playlists/{playlist_id}/tracks"
    add_track_payload = {"uris": [track_uri]}

    logging.debug("Adding track URI %s to playlist %s", track_uri, playlist_id)
    response_json = make_spotify_request(
        add_track_url, method="POST", data=add_track_payload
    )

    if response_json and (
        response_json.get("snapshot_id") or response_json.get("status_code") == 201
    ):
        print(f"Track '{track_name}' added successfully to playlist ID {playlist_id}.")
        logging.info(
            "Track '%s' (URI: %s) added. Snapshot ID: %s",
            track_name,
            track_uri,
            response_json.get("snapshot_id", "N/A"),
        )
    else:
        logging.error(
            "Failed to add track '%s' to playlist %s. Response: %s",
            track_name,
            playlist_id,
            response_json,
        )


# --- Main Execution ---
def main():
    """Main function to parse arguments and dispatch commands."""
    parser = argparse.ArgumentParser(
        description="A command-line tool to manage Spotify playlists.",
        epilog="Before first use, run 'login'. Ensure CLIENT_ID and CLIENT_SECRET are set in the script.",
    )
    parser.add_argument(
        "--loglevel",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: WARNING).",
    )

    subparsers = parser.add_subparsers(
        title="commands", dest="command", required=True, help="Available commands"
    )

    parser_login = subparsers.add_parser(
        "login", help="Authenticate with Spotify and store credentials."
    )
    parser_login.set_defaults(func=handle_login)

    parser_list = subparsers.add_parser("list", help="List all your Spotify playlists.")
    parser_list.set_defaults(func=handle_list_playlists)

    parser_get_tracks = subparsers.add_parser(
        "get-tracks", help="List tracks for a specific playlist."
    )
    parser_get_tracks.add_argument(
        "playlist_id", help="The ID of the playlist (e.g., from 'list' command)."
    )
    parser_get_tracks.set_defaults(func=handle_get_tracks)

    parser_create = subparsers.add_parser(
        "create", help="Create a new Spotify playlist."
    )
    parser_create.add_argument("name", help="Name for the new playlist.")
    parser_create.add_argument(
        "--description", help="Optional description for the playlist.", default=""
    )
    parser_create.add_argument(
        "--private",
        action="store_true",
        help="Make the playlist private (default is public).",
    )
    parser_create.add_argument(
        "--collaborative",
        action="store_true",
        help="Make the playlist collaborative (implies private).",
    )
    parser_create.set_defaults(func=handle_create_playlist)

    parser_add_track = subparsers.add_parser(
        "add-track", help="Search for a track and add it to a playlist."
    )
    parser_add_track.add_argument(
        "playlist_id", help="The ID of the playlist to add the track to."
    )
    parser_add_track.add_argument(
        "query", help="Search query for the track (e.g., 'Artist Name - Track Title')."
    )
    parser_add_track.set_defaults(func=handle_add_track)

    args = parser.parse_args()

    log_file_path = os.path.join(
        os.path.dirname(os.path.abspath(TOKEN_FILE)), "spotify_playlist.log"
    )
    logging.basicConfig(
        level=getattr(logging, args.loglevel.upper()),
        format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(module)s.%(funcName)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    logging.info(
        "Application started with command: %s, loglevel: %s",
        args.command,
        args.loglevel,
    )
    if CLIENT_ID == "YOUR_CLIENT_ID" or CLIENT_SECRET == "YOUR_CLIENT_SECRET":
        logging.warning(
            "CLIENT_ID or CLIENT_SECRET are placeholders. Login might fail or be limited."
        )
        if args.command != "login":
            print(
                "Warning: CLIENT_ID or CLIENT_SECRET are not configured in the script. Some operations may fail."
            )
            print(
                "Please edit spotify_playlist.py to set your Spotify API credentials."
            )

    if hasattr(args, "func"):
        try:
            args.func(args)
        except Exception as e:
            logging.critical(
                "An unhandled exception occurred in command '%s': %s",
                args.command,
                e,
                exc_info=True,
            )
            print(
                f"An unexpected error occurred: {e}. Check '{log_file_path}' for details."
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
