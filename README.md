<h1 align="center">Shodan Style Recon Engine</h1>

<div align="center">
<img src="info" alt="Information about my project">
</div>

## Overview

The Shodan Style Recon Engine is a powerful tool designed for vulnerability analysis and penetration testing. It leverages Masscan for high-speed network scanning and integrates with MongoDB to store and search the results. The web interface allows users to easily manage scans and search the database for specific information.

## Getting Started

This project is designed to run on Ubuntu, which can be set up via WSL on Windows.

### Prerequisites

- Python 3.x
- MongoDB
- Masscan

### Installation

1. **Clone the repository**
   ```sh
   git clone https://github.com/Barap1/Shodan-Style-Recon-Engine.git
   cd Shodan-Style-Recon-Engine
   ```
2. Install Masscan
   ```sh
    sudo apt-get --assume-yes install git make gcc
    git clone https://github.com/robertdavidgraham/masscan
    cd masscan
    make
    make install
   ```
3. Install Packages
   ```sh
   pip install asyncio pyopenssl aiohttp beautifulsoup4 Flask pymongo
   ```
4. Install MongoDB

    **[Install MongoDB on Ubuntu](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/)**

## Usage

1. Run the scanner - this may take some time depending on the amount of input
   ```sh
   python3 scanner.py
   ```

2. Run the server using gunicorn
   ```sh
   gunicorn -w 3 -b 0.0.0.0:5000 server:app
   ```

3. Navigate to *localhost:5000* to search the MongoDB database. You can also directly use mongosh or MongoDB Compass

## Roadmap

- [X] Add intuitive UI for searching
- [X] Incorporate scanner to run from web server
- [ ] Test with bug bounties


## License

Distributed under the MIT License. See `LICENSE.txt` for more information.
