# Spotify Playlist CLI

A command-line interface (CLI) tool for managing your Spotify playlists using the Spotify Web API.
This tool allows you to list playlists, view tracks, create new playlists, and add tracks directly from your terminal.

## Features

- **Authenticate:** Securely log in to your Spotify account using OAuth 2.0 with PKCE.
- **List Playlists:** View all your public and private playlists.
- **Get Tracks:** See the tracks within any of your playlists.
- **Create Playlists:** Easily create new playlists (public or private).
- **Add Tracks:** Search for songs on Spotify and add them to your chosen playlist (prevents duplicates).
- **Rate Limit Handling:** Respects Spotify API rate limits.
- **Token Management:** Securely stores and refreshes access tokens.

## Prerequisites

- **Python 3.8+:** Required to run the application.
- **Git:** Required by `pipx` to install from a GitHub repository.
- **pipx:** Recommended for installing Python CLI applications in isolated environments.
- **A Spotify Account:** To manage your playlists.

## Installation

### 1. Install Python 3 on Windows

If you don't have Python 3.8 or newer installed on Windows, follow these steps:

1. **Download Python:**

   - Go to the official Python website: `python.org/downloads/windows/`
   - Download the latest stable Python 3 installer (e.g., "Windows installer (64-bit)").

2. **Run the Installer:**

   - Open the downloaded installer.
   - **Important:** Check the box that says **"Add Python X.Y to PATH"** at the bottom of the first installer screen.
     This makes Python accessible from the command line.
   - Click "Install Now" for the recommended installation, or "Customize installation" if you need specific settings.
   - Follow the on-screen prompts to complete the installation.

3. **Verify Installation:**

   - Open Command Prompt (search for `cmd`) or PowerShell.
   - Type `python --version` and press Enter. You should see the installed Python version (e.g., `Python 3.11.4`).
   - Type `pip --version` and press Enter. You should see the pip version.

### 2. Install Git

If you don't have Git installed:

1. Go to `git-scm.com/download/win`.
2. Download and run the installer,
   accepting the default options is usually fine.

### 3. Install pipx

`pipx` is a tool to install and run Python applications in isolated environments.
It's a great way to keep your global Python environment clean.

1. Open Command Prompt or PowerShell.
2. Install `pipx` using pip (which comes with Python):

```bash
pip install --user pipx
```

3. Add `pipx` to your system's `PATH` (it usually prompts you to do this, or you can run):

```bash
pipx ensurepath
```

You may need to restart your terminal or Command Prompt for the `PATH` changes to take effect.

Installing from Github:

```bash
pipx install git+https://github.com/jonkensta/spotify-playlists-cli.git
```

This command will install the application and make the `spotify-playlist` command available globally.

## Usage

Once installed, you can use the application from your terminal.

### 1. Login (First Time)

You must log in the first time you use the application, or if your tokens expire and cannot be refreshed.

```bash
spotify-playlist login
```

This will:

- Open a Spotify authorization page in your web browser.
- Ask you to log in to Spotify and grant permissions to your application.
- Once authorized, it will store access and refresh tokens locally.

### 2. Available Commands

After logging in, you can use the following commands:

- **List your playlists:**

```bash
spotify-playlist list
```

- **Get tracks from a specific playlist:**

```bash
spotify-playlist get-tracks YOUR_PLAYLIST_ID
```

(Replace `YOUR_PLAYLIST_ID` with the actual ID from the `list` command output)

- **Create a new playlist:**

```bash
spotify-playlist create "My Awesome New Playlist"
```

Optional flags:

- `--description "A cool description"`
- `--private` (makes the playlist private, default is public)
- `--collaborative` (makes it collaborative, implies private)

- **Add a track to a playlist:**

spotify-playlist add-track YOUR_PLAYLIST_ID "Artist Name - Track Title"

(The script will search for the track and add the first result. It also checks for duplicates.)

- **Get help:**

```bash
spotify-playlist --help
spotify-playlist [command] --help
```

### Logging

The application logs its operations to `spotify_playlist.log` (located in the script's installation directory).
You can control the console logging verbosity with the `--loglevel` option:

```bash
spotify-playlist --loglevel DEBUG list
```

(Levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`)

## Contributing

Contributions are welcome!
Please feel free to fork the repository, make changes, and submit a pull request.

## License

This project is licensed under the UNLICENSE.
