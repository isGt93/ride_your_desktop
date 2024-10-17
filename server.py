from flask import Flask, request, jsonify
import sqlite3
import json
import os
import re
import logging

app = Flask(__name__)

# 设置日志记录

logging.basicConfig(filename='requests.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


# 初始化数据库
def init_db():
    if not os.path.exists('data.db'):
        with sqlite3.connect('data.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    os TEXT NOT NULL,
                    version TEXT NOT NULL,
                    architecture TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    processor TEXT NOT NULL,
                    cpu_cores INTEGER NOT NULL,
                    logical_cpus INTEGER NOT NULL,
                    memory TEXT NOT NULL,
                    disk TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    encryption_key TEXT NOT NULL,
                    visitor_ip TEXT NOT NULL
                )
            ''')
            conn.commit()


# 校验请求数据
def validate_data(data):
    required_fields = {
        '当前用户名': str,
        '操作系统': str,
        '系统版本': str,
        '系统架构': list,
        '主机名': str,
        '处理器': str,
        'CPU核心数': int,
        '逻辑CPU数': int,
        '内存信息': list,
        '磁盘信息': list,
        'IP地址': dict,
        'MAC地址': dict,
        '加密密钥': str,
    }
    for field, expected_type in required_fields.items():
        if field not in data:
            print("field:{}".format(field))
            return False
        if not isinstance(data[field], expected_type):
            print("field type:{}".format(field))
            return False

    return True


# 使用 before_request 钩子记录所有请求
@app.before_request
def log_request_info():
    if request.path.startswith('/api') and request.method == 'POST':
        # 对 /api 的 POST 请求不记录，因为它们会在单独的处理函数中记录
        return
    visitor_ip = request.remote_addr  # 获取访问者的 IP 地址
    method = request.method  # 获取 HTTP 方法
    path = request.path  # 获取请求路径
    query_params = request.args.to_dict()  # 获取查询参数
    body = request.get_json(silent=True) or {}  # 尝试获取 POST 请求体中的 JSON 数据
    logging.info("Request to %s from %s with method: %s, params: %s, body: %s",
                 path, visitor_ip, method, json.dumps(query_params, ensure_ascii=False),
                 json.dumps(body, ensure_ascii=False))


# 通配符路由，用于处理所有其他路径
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    if request.method == 'POST' and not request.path.startswith('/api'):
        # 这里可以处理非 /api 的 POST 请求
        return "200 OK (POST)", 200
    else:
        # 处理 GET 请求
        return "200 OK (GET)", 200


@app.route('/api', methods=['POST'])
def receive_data():
    data = request.get_json()
    visitor_ip = request.remote_addr
    # 校验数据
    if not validate_data(data):
        logging.warning("Invalid data from %s: %s", visitor_ip, json.dumps(data, ensure_ascii=False))
        return jsonify({"error": "请求数据异常"}), 400

    # 记录请求数据到日志文件
    logging.info("From %s Received data: %s", visitor_ip, json.dumps(data, ensure_ascii=False))

    # 插入数据到数据库
    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests (
                username, os, version, architecture, hostname, 
                processor, cpu_cores, logical_cpus, memory, disk, 
                ip_address, mac_address,encryption_key,visitor_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['当前用户名'],
            data['操作系统'],
            data['系统版本'],
            str(data['系统架构']),
            data['主机名'],
            data['处理器'],
            data['CPU核心数'],
            data['逻辑CPU数'],
            str(data['内存信息']),
            str(data['磁盘信息']),
            str(data['IP地址']),
            str(data['MAC地址']),
            data['加密密钥'],
            visitor_ip
        ))
        conn.commit()

    return jsonify({"message": "数据成功接收"}), 200


if __name__ == '__main__':
    init_db()  # 初始化数据库
    app.run(host='0.0.0.0', port=80) # 修改成你自己网站端口
