import os
import subprocess


class SSLChecker:

    def __init__(
        self,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips.txt",
        masscan_rate=10000,
    ):
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate

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

    def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()


if __name__ == "__main__":
    ssl_checker = SSLChecker()
    ssl_checker.main()
