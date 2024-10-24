<h1 align="center">Shodan Style Recon Engine</h1>

<br />
<div align="center">
  <a href="https://github.com/Barap1/Shodan-Style-Recon-Engine
    <img src="info" alt="info" >
  </a>
</div>


## Getting Started
Ubuntu is used for this project, this can be set up via WSL on Windows


### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/Barap1/Shodan-Style-Recon-Engine.git
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
   ```sh
   apt install gunicorn
   ```
4. Install MongoDB

    **[Install MongoDB on Ubuntu](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/)**

## Usage

1. Input the IP Subnets to be scanned into **ips.txt**

2. Run the scanner - this may take some time depending on the amount of input
   ```sh
   python3 scanner.py
   ```

3. Run the server using gunicorn
   ```sh
   gunicorn -w 3 -b 0.0.0.0:5000 server:app
   ```

4. Navigate to *localhost:5000* to search the MongoDB database. You can also directly use mongosh or MongoDB Compass

## Roadmap

- [X] Add intuitive UI for searching
- [ ] Incorporate scanner to run from web server
- [ ] Test with bug bounties


## License

Distributed under the MIT License. See `LICENSE.txt` for more information.
