from flask import Flask, request, make_response
from flask_cors import CORS
import pymongo
import pprint
import math


"""
/api/audit/ae: it gives the data regarding the severity level AE: all exceptions critical
/api/audit/ue: it gives the data regarding the unique Exceptions
/api/audit/oe: it gives the overview of the total exceptions
"""
app = Flask(__name__)
CORS(app)



def db_connect():
    """
    :return: returns the connection to the user
    """
    dbname = "CNA_Visualizer"
    dbclient = pymongo.MongoClient("mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb", 27017)
    db = dbclient[dbname]
    return db

def check_audit_info(customer_key, audit_id, audit_type):
    dbName = "CNA_Visualizer"
    dbClient = pymongo.MongoClient('localhost', 27017)
    db = dbClient[dbName]
    query = {"customer_key" : customer_key, "audit_id" : audit_id , "audit_type" : audit_type}
    res = db['upload_information'].find(query)
    result = list(res)
    print("Checking if audit is already available ... ")
    if len(result) == 0:
        print("Not found in the DB")
        return False
    else:
        print("Found in DB")
        return True


@app.route("/", methods=['GET'])
def default_route():
    if request.method == 'GET':
        print("sdfkjndsfkj")
        print(request.args.get("uname"))
        return {"great": "yes"}


@app.route("/api/get/audit", methods=['POST'])
def getdata():
    if request.method == 'POST':
        dbname = "CNA_Visualizer"
        audit_id = str(request.form['audit_id'])
        dbclient = pymongo.MongoClient("mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb", 27017)
        db = dbclient[dbname]  # here we are in the CNA visualizer
        query = {"jsonFor": "allExceptions"}
        res = db['12345'].find(query)
        result = list(res)

        return {"result": len(result)}

def get_json_overviewexceptions(cpykey, audit_1id, audit_2id):
    db = db_connect()
    all_data = []

    id_1 = audit_1id
    id_2 = audit_2id
    # gather total number of exceptions
    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions"})
    all_data.append({"name": "TNE", audit_1id: a1c, audit_2id: a2c})

    percent = find_percent(a1c, a2c)
    return all_data, percent


@app.route("/api/audit/oe", methods=["GET"])
def getoverview_exceptions():
    cpykey = request.args.get("cpykey")
    audit_1id = request.args.get("audit_1_id")
    audit_2id = request.args.get("audit_2_id")

    db = db_connect()
    r = db.get_collection(cpykey)
    if r is None:
        return {"error": "CpyKey is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_1id})

    if count is None:
        return {"error": "Audit-1 is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_2id})

    if count is None:
        return {"error": "Audit-2 is needed"}, 400

    result, p = get_json_overviewexceptions(cpykey, audit_1id, audit_2id)

    response = make_response({"result": result, "percent":p})
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response, 200


def getinfo_json(cpykey, audit_1id, audit_2id):
    db = db_connect()
    all_data = []
    result1 = db.get_collection(cpykey).find_one({"jsonFor": "audit_information", "Audit_ID": audit_1id})
    del result1["_id"]
    result1["cpykey"] = cpykey

    all_data.append(result1)

    result2 = db.get_collection(cpykey).find_one({"jsonFor": "audit_information", "Audit_ID": audit_2id})
    del result2["_id"]
    result2["cpykey"] = cpykey
    all_data.append(result2)

    return all_data


@app.route("/api/audit/info", methods=["GET"])
def getinfo():
    cpykey = request.args.get("cpykey")
    audit_1id = request.args.get("audit_1_id")
    audit_2id = request.args.get("audit_2_id")
    print(cpykey)
    print(audit_1id)
    print(audit_2id)

    db = db_connect()
    r = db.get_collection(cpykey)
    if r is None:
        return {"error": "CpyKey is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_1id})

    if count is None:
        return {"error": "Audit-1 is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_2id})

    if count is None:
        return {"error": "Audit-2 is needed"}, 400

    result = getinfo_json(cpykey, audit_1id, audit_2id)

    response = make_response({"result": result})
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response, 200


def find_percent(num1, num2):
    if num1 == 0 and num2 == 0:
        return 0
    p = int(((num1-num2)/(num1+num2))*100)
    # p > 0 : decrement in exceptions
    # p < 0 : increment in exceptions
    percent = None
    if p > 0:
        percent = {"p": abs(p), "diff": "decrement"}
    elif p < 0:
        percent = {"p": abs(p), "diff": "increment"}
    else:
        percent = {"p": abs(p), "diff": "constant"}

    return percent


def get_json_allexceptions(cpykey, audit_1id, audit_2id):
    """
    input: it takes the company key and audit list to be compared
    TNE-C: total number of critical exceptions
    TNE-H: total number of high severity exceptions
    TNE-M: medium severity
    TNE-L: low severity
    TNE-I: informational severity

    :return: it returns the json for the audit id
    """
    db = db_connect()
    all_data = []

    id_1 = audit_1id
    id_2 = audit_2id

    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions", "Severity": "Critical"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions", "Severity": "Critical"})
    all_data.append({"name": "Critical", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions", "Severity": "High"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions", "Severity": "High"})
    all_data.append({"name": "High", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions", "Severity": "Medium"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions", "Severity": "Medium"})
    all_data.append({"name": "Medium", audit_1id: a1c, audit_2id: a2c, "percent":find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions", "Severity": "Low"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions", "Severity": "Low"})
    all_data.append({"name": "Low", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents({"Audit_ID": id_1, "jsonFor": "allExceptions", "Severity": "Informational"})
    a2c = db.get_collection(cpykey).count_documents({"Audit_ID": id_2, "jsonFor": "allExceptions", "Severity": "Informational"})
    all_data.append({"name": "Info", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    count_1 = all_data[0][audit_1id]
    count_2 = all_data[0][audit_2id]
    percent = find_percent(count_1, count_2)

    return all_data, percent


@app.route("/api/audit/ae", methods=["GET"])
def getAllExceptions():
    cpykey = request.args.get("cpykey")
    audit_1id = request.args.get("audit_1_id")
    audit_2id = request.args.get("audit_2_id")

    db = db_connect()
    r = db.get_collection(cpykey)
    if r is None:
        return {"error": "CpyKey is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_1id})

    if count is None:
        return {"error": "Audit-1 is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_2id})

    if count is None:
        return {"error": "Audit-2 is needed"}, 400

    result, p = get_json_allexceptions(cpykey, audit_1id, audit_2id)

    response = make_response({"result": result, "percent": p})
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response, 200


def get_json_fccaps(cpykey, audit_1id, audit_2id):
    db = db_connect()
    all_data = []
    id_1 = audit_1id
    id_2 = audit_2id

    a1c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_1,"jsonFor":"allExceptions", "NMS Area": "Fault Management"})
    a2c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_2,"jsonFor":"allExceptions", "NMS Area": "Fault Management"})
    all_data.append({"name": "FM", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_1,"jsonFor":"allExceptions", "NMS Area": "Capacity Management"})
    a2c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_2, "jsonFor":"allExceptions", "NMS Area": "Capacity Management"})
    all_data.append({"name": "CM", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_1,"jsonFor":"allExceptions", "NMS Area": "Configuration Management"})
    a2c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_2,"jsonFor": "allExceptions", "NMS Area": "Configuration Management"})
    all_data.append({"name": "COM", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_1,"jsonFor":"allExceptions", "NMS Area": "Performance Management"})
    a2c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_2,"jsonFor":"allExceptions", "NMS Area": "Performance Management"})
    all_data.append({"name": "PM", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    a1c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_1,"jsonFor":"allExceptions", "NMS Area": "Security Management"})
    a2c = db.get_collection(cpykey).count_documents(
        {"Audit_ID": id_2,"jsonFor":"allExceptions", "NMS Area": "Security Management"})
    all_data.append({"name": "SM", audit_1id: a1c, audit_2id: a2c, "percent": find_percent(a1c, a2c)})

    return all_data

@app.route("/api/audit/fccaps", methods=["GET"])
def getfccaps():
    cpykey = request.args.get("cpykey")
    audit_1id = request.args.get("audit_1_id")
    audit_2id = request.args.get("audit_2_id")

    db = db_connect()
    r = db.get_collection(cpykey)
    if r is None:
        return {"error": "CpyKey is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_1id})

    if count is None:
        return {"error": "Audit-1 is needed"}, 400

    count = db.get_collection(cpykey).find_one({"Audit_ID": audit_2id})

    if count is None:
        return {"error": "Audit-2 is needed"}, 400
    result= get_json_fccaps(cpykey, audit_1id, audit_2id)

    response = make_response({"result": result})
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response, 200


def get_json_unique_exceptions(cpykey, audit_1id, audit_2id):
    """

    :param cpykey:
    :param audit_1id:
    :param audit_2id:
    :return: the unique exceptions in an audit file
    """
    db = db_connect()
    result1 = db.get_collection(cpykey).distinct("Exception Name", {"Audit_ID": audit_1id})
    result2 = db.get_collection(cpykey).distinct("Exception Name", {"Audit_ID": audit_2id})
    print(result1)
    print(result2)
    all_data = [{"name": "Unique Exceptions", audit_1id: len(result1), audit_2id: len(result2)}]

    percent = find_percent(len(result1), len(result2))

    return all_data, percent


@app.route("/api/audit/ue", methods=["GET"])
def getunique_exceptions():
    cpykey = request.args.get("cpykey")
    audit_1id = request.args.get("audit_1_id")
    audit_2id = request.args.get("audit_2_id")
    result, p = get_json_unique_exceptions(cpykey, audit_1id, audit_2id)

    response = make_response({"result": result, "percent": p})
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response, 200


@app.route("/api/upload", methods=['POST'])
def upload():
    """
    this function is used to upload the audits from the user
    :return: it returns the status code for the frontend
    """
    if request.method == 'POST':
        # init the data for storing the input from the starting page
        # two audits with name audit 1 and audit 2
        data = {}
        if "cec_id" in request.form and "audit1_type" in request.form and "audit2_type" in request.form:
            # complete the if statement
            # these are the files
            cec_id = str(request.form['cec_id'])
            top_id = str(request.form['top_id'])
            cpy_key = str(request.form['cpy_key'])
            cname = str(request.form['cname'])
            audit1_id = str(request.form['audit1_id'])
            audit1_type = request.form['audit1_type']
            audit2_id = str(request.form['audit2_id'])
            audit2_type = request.form['audit2_type']

            if cec_id and cpy_key and audit1_id and audit2_id and audit2_type and audit1_type:
                # creating the data object using all the data
                data['cec_id'] = cec_id
                data['top_id'] = top_id
                data['cpy_key'] = cpy_key
                data['cname'] = cname
                data['audit1_id'] = audit1_id
                data['audit2_id'] = audit2_id
                data['audit1_type'] = audit1_type
                data['audit2_type'] = audit2_type

                print(data)
                return {"message": "success"}, 200
            else:
                return {"error": "Error Format in request"}, 400
        else:
            return {"error": "Error format in request header"}, 400


def get_json_np(cpykey, audit_1id, audit_2id):
    """
        ne: not present
        it returns the exceptions that are present in the old audit, but "not present" in the new audit
        if length == 0: it returns false, or else it returns true with the list
        :return:
    """
    db = db_connect()

    list1 = db.get_collection(cpykey).distinct("Exception Name", {"jsonFor": "allExceptions", "Audit_ID": audit_1id})
    list2 = db.get_collection(cpykey).distinct("Exception Name", {"jsonFor": "allExceptions", "Audit_ID": audit_2id})
    result_set_1 = set(list1) - set(list2)
    result_set_2 = set(list2) - set(list1)
    result_list_1 = [i for i in result_set_1]
    result_list_2 = [i for i in result_set_2]
    method_1 = True
    method_2 = True
    if len(result_set_1) == 0:
        method_1 = False
    if len(result_set_2) == 0:
        method_2 = False

    return {"a1": {"method": method_1, "length": len(result_list_1), "result": result_list_1},
            "a2": {"method": method_2, "length": len(result_list_2), "result": result_list_2}}


@app.route("/api/audit/get/table/np", methods=["GET"])
def np():
    if request.method == "GET":
        cpykey = request.args.get("cpykey")
        audit_1id = request.args.get("audit_1_id")
        audit_2id = request.args.get("audit_2_id")
        result = get_json_np(cpykey, audit_1id, audit_2id)

        response = make_response({"result": result})
        response.headers['Access-Control-Allow-Origin'] = '*'

        return response, 200


if __name__ == "__main__":
    app.run(debug=True)