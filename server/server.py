import re
import json
from bson.regex import Regex
from pymongo import MongoClient
from flask import Flask, request, jsonify, Response, render_template
import subprocess
import os
import time
import signal

app = Flask(__name__)
STATUS_FILE = "status.json"
scanner_process = None
scanner_start_time = None  

# Function to update the status file (only status)
def update_status_file(status, start_time=None):
    data = {"status": status}
    if start_time is not None:
        data["start_time"] = start_time
    with open(STATUS_FILE, "w") as f:
        json.dump(data, f)

update_status_file("not running")

def check_status_file():
    with open(STATUS_FILE, "r") as f:
        data = json.load(f)
    return data["status"]



with open("chunks_processed.json", "w") as f:
    json.dump({"chunks_processed": 0}, f)

# MongoDB configuration
mongo_uri = "mongodb://localhost:27017/"
client = MongoClient(mongo_uri)

try:
    db = client["scannerdb"]
    collection = db["sslchecker"]
    print("MongoDB connection successful")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")

"""
@app.errorhandler(Exception)
def handle_database_error(e):
  return "An error occurred while connecting to the database.", 500
"""

@app.route("/", methods=["GET"])
def home():
  return render_template("index.html")


@app.route("/<path:any_path>", methods=["GET"])
def respond_to_any_path(any_path):
  # Here, 'any_path' will capture any URL path as a variable
  return render_template("404.html")  # Render a 404 page

@app.route("/insert", methods=["POST"])
def insert():
    try:
        # get json data from the request object
        results_json = request.get_json()
        collection.insert_many(results_json)

        # Update the number of chunks processed
        with open("chunks_processed.json", "r") as f:
            data = json.load(f)
        data["chunks_processed"] += 1
        with open("chunks_processed.json", "w") as f:
            json.dump(data, f)

        return jsonify({"message": "Inserted"})

    except Exception as e:
        print(f"Error inserting data into the database: {str(e)}")
        return jsonify({"error": str(e)}), 500



@app.route("/add_ip", methods=["POST"])
def add_ip():
    try:
        ip_address = request.form["ip_address"]
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400

        with open("../ips.txt", "a") as f:
            f.write(f"{ip_address}\n")

        return jsonify({"message": "IP address added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/bytitle", methods=["GET"])
def bytitle():
    try:
        title_param = request.args.get("bytitle")

        if title_param is None:
            return jsonify({"error": "title query parameter is missing"}), 400
            # escape any special characters such as dot if it exists in the title_param
        regex_pattern = rf".*{re.escape(title_param)}.*"
        # match the exact value only if it's included in the title
        regex = Regex(regex_pattern, "i")  # "i" flag makes it case-insensitive
        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None

        # Query MongoDB to find documents with the specified "title" in any key
        query = {
            "$or": [
                {"http_responseForIP.title": regex},
                {"https_responseForIP.title": regex},
                {"http_responseForDomainName.title": regex},
                {"https_responseForDomainName.title": regex},
            ]
        }
        # collection.find returns documents
        matching_entries = list(collection.find(query, {"_id": 0}))
        total_entries = len(matching_entries)
        # Adjust the indices if they are out of bounds
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        # get the entries from:to ,from the entered values in query parameters and remove _id field before returning the response
        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        json_response = json.dumps(response, indent=4)

        # Create a Response object with the JSON content type
        return Response(json_response, content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# http://localhost:5000/bydomain?domain=something.com
@app.route("/bydomain", methods=["GET"])
def bydomain():
    try:
        domain_param = request.args.get("bydomain")

        if domain_param is None:
            return jsonify({"error": "domain query parameter is missing"}), 400

        regex_pattern = rf".*{re.escape(domain_param)}.*"
        regex = Regex(regex_pattern, "i")
        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None

        query = {
            "$or": [
                {"http_responseForIP.domain": regex},
                {"https_responseForIP.domain": regex},
                {"http_responseForDomainName.domain": regex},
                {"https_responseForDomainName.domain": regex},
            ]
        }

        matching_entries = list(collection.find(query, {"_id": 0}))
        total_entries = len(matching_entries)
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        json_response = json.dumps(response, indent=4)

        return Response(json_response, content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# http://localhost:5000/byip?ip=192.168.0.1
@app.route("/byip", methods=["GET"])
def byip():
    try:
        ip_param = request.args.get("byip")

        if ip_param is None:
            return jsonify({"error": "ip query parameter is missing"}), 400

        regex_pattern = rf".*{re.escape(ip_param)}.*"
        regex = Regex(regex_pattern, "i")
        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None

        query = {"ip": regex}

        matching_entries = list(collection.find(query, {"_id": 0}))
        total_entries = len(matching_entries)
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        json_response = json.dumps(response, indent=4)

        return Response(json_response, content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# http://localhost:5000/byport?port=8000&from=0&to=10
@app.route("/byport", methods=["GET"])
def byport():
    try:
        port_param = request.args.get("byport")

        if port_param is None:
            return jsonify({"error": "port query parameter is missing"}), 400

        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None

        query = {"ports.port": int(port_param)}

        matching_entries = list(collection.find(query, {"_id": 0}))
        total_entries = len(matching_entries)
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        json_response = json.dumps(response, indent=4)

        return Response(json_response, content_type="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# gets all the response headers related to the given value in the hresponse query parameter
# Pagination, just apply the size to see the number of results returned
# http://localhost:5000/byhresponse?hresponse=er&from=0&to=10
@app.route("/byhresponse", methods=["GET"])
def byhresponse():
    try:
        hresponse_param = request.args.get("byhresponse")

        if hresponse_param is None:
            return jsonify({"error": "hresponse query parameter is missing"}), 400

        regex_pattern = rf".*{re.escape(hresponse_param)}.*"
        regex = Regex(regex_pattern, "i")
        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None
        # get all the documents from DB and convert the result into list
        all_documents = list(collection.find({}))
        matching_entries = []

        # Iterate through each document with a specific key,It first loops http_responseForDomainName, then https_responseForDomainName , then https_responseForIP
        for document in all_documents:
            for keyName in [
                "http_responseForDomainName",
                "https_responseForDomainName",
                "https_responseForIP",
            ]:
                # document.get will return the dictionary associated with the key,eg http_responseForDomainName,in each document we have a field such as http_responseForDomainName so just get that field which is a dictionary
                field = document.get(keyName)
                if field:
                    # loop the keys of each field,since field is a dictionary,we can get the key like this:
                    for key in field:
                        if "response_headers" in key:
                            response_headers = field["response_headers"]
                            for resp_header_value in response_headers.values():
                                if hresponse_param.lower() in resp_header_value.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)

        # http_responseForIP is an array of objects so I will iterate it
        for document in all_documents:
            # this time document.get will return an array/list of dictionaries
            array_of_dictionaries = document.get("http_responseForIP")
            if array_of_dictionaries:
                for dictionary_item in array_of_dictionaries:
                    for key in dictionary_item:
                        if "response_headers" in key:
                            response_headers = dictionary_item["response_headers"]
                            for header_value in response_headers.values():
                                if hresponse_param.lower() in header_value.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)

        total_entries = len(matching_entries)

        # Adjust the indices if they are out of bounds
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        # get the entries from:to ,from the entered values in query parameters and remove _id field before returning the response
        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        # Manually serialize to JSON and guarantee the order of the returned key/value pairs
        json_response = json.dumps(response, indent=4)

        # Create a Response object with the JSON content type
        return Response(json_response, content_type="application/json")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Search by keys in the response header
# http://localhost:5000/byhkeyresponse?hkeyresponse=Content-Security-Policy&from=0&to=10
@app.route("/byhkeyresponse", methods=["GET"])
def byhkeyresponse():
    try:
        hkeyresponse_param = request.args.get("byhkeyresponse")

        if hkeyresponse_param is None:
            return jsonify({"error": "hkeyresponse query parameter is missing"}), 400

        regex_pattern = rf".*{re.escape(hkeyresponse_param)}.*"
        regex = Regex(regex_pattern, "i")
        from_index = int(request.args.get("from", 0))
        to_index = request.args.get("to", None)
        to_index = int(to_index) if to_index is not None else None
        # get all the documents from DB and convert the result into list
        all_documents = list(collection.find({}))
        matching_entries = []

        for document in all_documents:
            for keyName in [
                "http_responseForDomainName",
                "https_responseForDomainName",
                "https_responseForIP",
            ]:
                # document.get will return the dictionary associated with the key,eg http_responseForDomainName,in each document we have a field such as http_responseForDomainName so just get that field which is a dictionary
                field = document.get(keyName)
                if field:
                    # loop the keys of each field,since field is a dictionary,we can get the key like this:
                    for key in field:
                        if "response_headers" in key:
                            response_headers = field["response_headers"]
                            for resp_key_value in response_headers.keys():
                                if hkeyresponse_param.lower() in resp_key_value.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)

        for document in all_documents:
            array_of_dictionaries = document.get("http_responseForIP")
            if array_of_dictionaries:
                for dictionary_item in array_of_dictionaries:
                    for key in dictionary_item:
                        if "response_headers" in key:
                            response_headers = dictionary_item["response_headers"]
                            for header_key in response_headers.keys():
                                if hkeyresponse_param.lower() in header_key.lower():
                                    document["_id"] = str(document["_id"])
                                    matching_entries.append(document)

        total_entries = len(matching_entries)

        # Adjust the indices if they are out of bounds
        from_index = max(0, min(from_index, total_entries))
        to_index = min(total_entries, max(to_index, 0)) if to_index is not None else total_entries

        # get the entries from:to ,from the entered values in query parameters and remove _id field before returning the response
        paginated_entries = []
        for entry in matching_entries[from_index:to_index]:
            entry.pop("_id", None)
            paginated_entries.append(entry)

        response = {"total_entries": total_entries, "entries": paginated_entries}
        # Manually serialize to JSON and guarantee the order of the returned key/value pairs
        json_response = json.dumps(response, indent=4)

        # Create a Response object with the JSON content type
        return Response(json_response, content_type="application/json")

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# route to delete the entire MongoDB collection
@app.route("/delete", methods=["GET"])
def delete():
  return render_template("delete_confirmation.html")


# JavaScript code in the template will call this function
@app.route("/perform_delete", methods=["DELETE"])
def perform_delete():
  try:
    # Delete all documents in the collection
    result = collection.delete_many({})

    return jsonify({"message": f"Deleted {result.deleted_count} documents"}), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500

@app.route("/scan", methods=["POST"])
def scan():
    global scanner_process

    if str(check_status_file()) == "running":
        return jsonify({"error": "Scanner is already running"}), 400
    else:
        try:
            masscan_rate = request.form["masscan_rate"]
            timeout = request.form["timeout"]
            chunkSize = request.form["chunkSize"]
            ports = request.form["ports"]

            scanner_path = os.path.join(os.path.dirname(__file__), '..', 'scanner.py')
            command = f"python3 {scanner_path} {masscan_rate} {timeout} {chunkSize} {ports}"
            print(f"Running command: {command}")

            scanner_start_time = time.time()
            scanner_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
            # Update status to "running" and include start time
            update_status_file("running", scanner_start_time)

            return jsonify({"message": "Scanner started successfully"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route("/scanstatus", methods=["GET"])
def scan_status():
    """Reads the status from the status.json file and calculates elapsed time."""
    try:
        with open(STATUS_FILE, "r") as f:
            status_data = json.load(f)
            status = status_data["status"]
            start_time = status_data.get("start_time", 0)
    except (FileNotFoundError, json.JSONDecodeError):
        # File not found or invalid JSON
        return jsonify({"status": "not running", "elapsed_time": 0}), 200

    if status == "running":
        elapsed_time = int(time.time() - start_time)  # Calculate elapsed time here
    else:
        elapsed_time = 0

    return jsonify({"status": status, "elapsed_time": elapsed_time}), 200

@app.route("/scanchunks", methods=["GET"])
def get_chunks_processed():
    try:
        with open("status.json", "r") as g:
            stat = json.load(g)
            if stat["status"] == "running":
                with open("chunks_processed.json", "r") as f:
                    data = json.load(f)
                return jsonify(data), 200
            else:
                return jsonify({"chunks_processed": 0}), 200
    except:
        return jsonify({"chunks_processed": 0}), 200
    
@app.route("/scanstop", methods=["POST"])
def stop_scan():
    global scanner_process

    try:
        if str(check_status_file()) == "running":
            update_status_file("stopped")
            # Send SIGTERM to the process group
   
            if scanner_process:
                os.kill(int(scanner_process.pid), signal.SIGKILL)
            time.sleep(1)
            os.killpg(os.getpgid(scanner_process.pid), signal.SIGKILL)
            scanner_process.wait()

            scanner_process = None
            
            return jsonify({"message": "Scanner stopped successfully"}), 200
        else:
            return jsonify({"message": "No scanner process is running"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to stop scanner: {e}"}), 200

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)