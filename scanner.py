import re
import ssl
import os
import subprocess
import asyncio
import json
import aiohttp
from OpenSSL import crypto
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup, SoupStrainer
class SSLChecker:

    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips.txt",
        masscan_rate=10000,
        timeout=2,
        chunkSize=2000,
        MAX_CONCURRENT=100,
        semaphore_limit=70, 
        ports=[80],
        protocols=["http://", "https://"],
        server_url="http://127.0.0.1:5000/insert"
    ):
        self.ssl_port = ssl_port
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.protocols = protocols
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.ports=ports
        self.server_url=server_url
        self.MAX_CONCURRENT = MAX_CONCURRENT

    def is_valid_domain(self, common_name):
        # checks using regex to see if the domain is real
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(domain_pattern, common_name) is not None

    async def makeGetRequest(self,session,protocol, ip, common_name, makeRequestByIP=True):
        async def parseResponse(url,port):
            try:
                if self.semaphore.locked():
                    await asyncio.sleep(1)

                    redirected_domain=""
                    response_headers={}
                    first_300_words=""
                    title=""

                    async with session.get(url,allow_redirects=True,timeout=self.timeout,ssl=False) as res:
                        response=await res.text(encoding="utf-8")
                        content_type=res.headers.get("Content-Type")

                        if res.headers is not None:
                            for key, value in res.headers.items():
                                response_headers[key] = value.encode("utf-8", "surrogatepass").decode("utf-8")
                
                        if res.history:
                            redirected_domain = str(res.url)

                        if response is not None and content_type is not None:
                            if "xml" in content_type:
                                root=ET.fromstring(response)
                                xmlwords=[]
                                count=0

                                for elem in root.iter():
                                    if elem.text:
                                        xmlwords.extend(elem.text.split())
                                        count += len(xmlwords)
                                        if count >=300:
                                            break
                                if xmlwords:
                                    first_300_words = " ".join(xmlwords[:300])

                            elif "html" in content_type:
                                 strainer = SoupStrainer(["title","body"])
                                 soup=BeautifulSoup(response, 'html.parser',parse_only=strainer)
                                 title_tag=soup.title
                                 body_tag=soup.body

                                 if title_tag and title_tag.string:
                                     title = title_tag.string.strip()

                                 if body_tag:
                                    body_text = body_tag.get_text(separator=" ", strip=True)
                                    words = body_text.split()
                                    first_300_words = " ".join(words[:300])

                                 if not body_tag or not title_tag:
                                    words= response.split()
                                    first_300_words=" ".join(words[:300])

                            elif "plain" in content_type:
                                words=response.split()
                                first_300_words = " ".join(words[:300])

                            elif "json" in content_type:
                                first_300_words = " ".join(words[:300])

                            if makeRequestByIP:
                                print(f"Title: {title}, {protocol}{ip}:{port}")
                            else:
                                print(f"Title: {title}, {protocol}{common_name}:{port}")

                            result_dict= {
                                "title":title.encode("utf-8", "surrogatepass").decode("utf-8"),
                                "request":f"{protocol}{ip if makeRequestByIP else common_name}:{port}",
                                "redirected_url":redirected_domain,
                                "ip":ip,
                                "port": str(port),
                                "domain":common_name,
                                "response text": first_300_words,
                                "response_headers":response_headers
                            }
                            return result_dict

            except ET.ParseError as e:
                print(f"Error parsing XML: {e}")

            except Exception as e:
                if makeRequestByIP:
                    print(f"Error for: {protocol}{ip}:{port}, {e}")
                else:
                    print(f"Error for: {protocol}{common_name}:{port}, {e}")

            return None
        
        url = ""
        if makeRequestByIP:
            if protocol == "http://":
                httpResults=[]
                for port in self.ports:
                    url = f"{protocol}{ip}:{port}"
                    result = await parseResponse(url,port)
                    if result is not None:
                        httpResults.append(result)
                if httpResults:
                    return httpResults
                else:
                    return None
            else:
                url=f"{protocol}{ip}:{self.ssl_port}"
                return await parseResponse(url,self.ssl_port)
        else:
            port="80" if protocol =="http://" else self.ssl_port
            url = f"{protocol}{common_name}:{port}"
            return await parseResponse(url,port)
            

    async def check_site(self, session, ip, common_name):
        try:
            async with self.semaphore:  # lets us limit teh amount of requests sent so that it is reasonable
                temp_dict = {}

                # sends request using ip address and ip address and domain name if available
                if "*" in common_name or not self.is_valid_domain(common_name):
                    for protocol in self.protocols:
                        # request with ip
                        dict_res = await self.makeGetRequestToDomain(session, protocol, ip, common_name, True)
                        temp_dict[f'{protocol.replace("://", "")}_responseForIP'] = dict_res

                else:
                    for protocol in self.protocols:
                        # request only with common name
                        dict_res = await self.makeGetRequestToDomain(session, protocol, ip, common_name, False)
                        temp_dict[f'{protocol.replace("://", "")}_responseForDomainName'] = dict_res

                    for protocol in self.protocols:
                        # request with ip
                        dict_res = await self.makeGetRequestToDomain(session, protocol, ip, common_name, True)
                        temp_dict[f'{protocol.replace("://", "")}_responseForIP'] = dict_res

                    temp_dict = {k: v for k,
                                 v in temp_dict.items() if v is not None}
                    if temp_dict:
                        return temp_dict

        except Exception as e:
            print("Error for ", ip, ":", e)

    async def fetch_certificates(self, ip):
        try:
            # passion function through thhe thread so that it is not blocked by rest of code
            cert = await asyncio.to_thread(ssl.get_server_certificate, (ip, self.ssl_port), timeout=self.timeout)
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            # retreives information from the certificate after decoding
            subject = x509.get_subject()
            common_name = subject.CN
            print(common_name)

            return ip, common_name

        except Exception as e:
            print(f"Error for {ip}: {e}")

        return ip, ""

    async def extract_domains(self):
        # reads the file of ips that nassscan outpus and then uses aiohttp to send requests to them. It then also uses the fetch_certificates function
        # to get common names
        try:
            with open(self.mass_scan_results_file, "r") as file:
                content = file.read()

            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\."
            ip_addresses = re.findall(ip_pattern, content)

            # Sends requests to the ips more efficiently by sending them in different oders
            for i in range(0, len(ip_addresses), self.chunkSize):
                # creates the session to make requests
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT, ssl=False)) as session:
                    chunk_Of_IPs = ip_addresses[i:i+self.chunkSize]
                    io_and_common_names = []

                    # Uses a single thread with a event loop. asyncio sends the funtion for a get request but doesn't wait for a response
                    ip_and_common_names = await asyncio.gather(*[self.fetch_certificates(ip) for ip in chunk_Of_IPs])

                    allResponses = await asyncio.gather(
                        *[
                            self.check_site(session, ip, common_name)
                            for ip, common_name in ip_and_common_names
                        ]
                    )

                    allResponses = [response for response in allResponses if response if response is not None]

                    results_json = json.dumps(allResponses)
                    headers = {"Content-Type":"application/json"}

                    async with session.post(self.server_url, data=results_json, headers=headers, ssl=False) as res:
                        if res.status == 201 or res.status == 200:
                            print("****Results inserted successfully****")
                        else:
                            print(f"Failed to insert results. Status code: {res.status}")
                        
                        print(await res.text())

                        await session.close()

                        del allResponses
                        del results_json
                        del ip_and_common_names

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def run_masscan(self):
        try:
            # port 443 is usually where developers store ssl certificates
            command = f"sudo masscan -p 443 --rate {self.masscan_rate} --wait 0 -iL {self.ips_file} -oH {self.mass_scan_results_file}"
            # lets us run commands
            subprocess.run(command, shell=True, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")

        except FileNotFoundError:
            print("Masscan exacutable not found")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def check_and_create_files(self, *file_paths):
        for file_path in file_paths:
            if not os.path.exists(file_path):
                with open(file_path, "w") as file:
                    pass
                print(f'File "{file_path}" has been created')

    async def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()
        await self.extract_domains()


if __name__ == "__main__":
    ssl_checker = SSLChecker()
    # creates a new event loop for the duration of the call
    asyncio.run(ssl_checker.main())
