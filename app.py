from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import os
import hashlib
import re
import struct
import subprocess
import base64
from datetime import datetime
from werkzeug.utils import secure_filename
from jinja2 import select_autoescape
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from cryptography.exceptions import InvalidSignature
import binascii

app = Flask(__name__)
app.config['SECRET_KEY'] = 'R94u5>/3}B.yjk£bD'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

app.jinja_env.autoescape = select_autoescape(['html', 'xml'])
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


ALLOWED_EXTENSIONS = {'bin'}

@app.template_filter('format_version')
def format_version_filter(version_str):
    if not version_str:
        return "Неизвестно"
    return f"v{version_str}"

@app.template_filter('format_filesize')
def format_filesize_filter(size_bytes):
    if size_bytes == 0:
        return "0 Б"
    size_names = ["Б", "КБ", "МБ", "ГБ"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {size_names[i]}"

@app.template_filter('format_datetime')
def format_datetime_filter(dt, format='%d.%m.%Y %H:%M'):
    if isinstance(dt, str):
        return dt
    return dt.strftime(format) if dt else "Неизвестно"

@app.template_filter('highlight_version')
def highlight_version_filter(current_version, latest_version):
    if not current_version or not latest_version:
        return "text-muted"
    
    try:
        current_parts = [int(x) for x in current_version.split('.')]
        latest_parts = [int(x) for x in latest_version.split('.')]
        
        for i in range(min(len(current_parts), len(latest_parts))):
            if current_parts[i] < latest_parts[i]:
                return "text-warning"
            elif current_parts[i] > latest_parts[i]:
                return "text-success"
        
        if len(current_parts) < len(latest_parts):
            return "text-warning"
        elif len(current_parts) > len(latest_parts):
            return "text-success"
        
        return "text-success"
    except:
        return "text-muted"

@app.template_filter('status_badge')
def status_badge_filter(is_latest):
    return "bg-success" if is_latest else "bg-warning"

@app.template_filter('status_text')
def status_text_filter(is_latest):
    return "Актуальная версия" if is_latest else "Доступно обновление"

@app.template_filter('status_icon')
def status_icon_filter(is_latest):
    return "fas fa-check-circle" if is_latest else "fas fa-exclamation-triangle"

@app.template_global()
def get_current_year():
    return ("2020-2025")

@app.template_global()
def get_app_version():
    return "1.2.0"

@app.template_global()
def get_company_name():
    return "AMMAG TECHNOLOGIES LLP"

@app.template_global()
def generate_breadcrumb(page_name):
    breadcrumbs = [
        {'name': 'Главная', 'url': url_for('index'), 'active': False}
    ]
    
    if page_name == 'result':
        breadcrumbs.append({
            'name': 'Результат проверки', 
            'url': '#', 
            'active': True
        })
    
    return breadcrumbs

@app.template_global()
def get_file_info(filename):
    """Возвращает информацию о файле"""
    if not filename:
        return None
    
    return {
        'name': filename,
        'extension': filename.split('.')[-1] if '.' in filename else '',
        'size_display': 'Неизвестно'
    }

@app.template_test('outdated')
def is_outdated_test(current_version, latest_version):
    if not current_version or not latest_version:
        return False
    
    try:
        current_parts = [int(x) for x in current_version.split('.')]
        latest_parts = [int(x) for x in latest_version.split('.')]
        
        for i in range(min(len(current_parts), len(latest_parts))):
            if current_parts[i] < latest_parts[i]:
                return True
            elif current_parts[i] > latest_parts[i]:
                return False
        
        return len(current_parts) < len(latest_parts)
    except:
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_structured_format(data):
    try:
        offset = 0
        result = {}
        

        if len(data) < 8 or data[:4] != b'BINF':
            return None
        
        print(f"Найден заголовок BINF, размер файла: {len(data)} байт")
        offset = 4
        

        if offset + 4 <= len(data):
            version_bytes = data[offset:offset+4]
            major, minor, patch, build = struct.unpack('BBBB', version_bytes)
            result['version'] = f"{major}.{minor}.{patch}.{build}"
            offset += 4
            print(f"Версия: {result['version']}")
        

        if offset + 2 <= len(data):
            name_length = struct.unpack('H', data[offset:offset+2])[0]
            offset += 2
            print(f"Длина имени: {name_length}")
            
            if offset + name_length <= len(data):
                name_bytes = data[offset:offset+name_length]
                result['name'] = name_bytes.decode('utf-8', errors='ignore')
                offset += name_length
                print(f"Имя: {result['name']}")
        

        if offset + 2 <= len(data):
            org_length = struct.unpack('H', data[offset:offset+2])[0]
            offset += 2
            print(f"Длина организации: {org_length}")
            
            if offset + org_length <= len(data):
                org_bytes = data[offset:offset+org_length]
                result['organization'] = org_bytes.decode('utf-8', errors='ignore')
                offset += org_length
                print(f"Организация: {result['organization']}")
        
        if offset + 2 <= len(data):
            software_length = struct.unpack('H', data[offset:offset+2])[0]
            offset += 2
            print(f"Длина ПО: {software_length}")
            
            if offset + software_length <= len(data):
                software_bytes = data[offset:offset+software_length]
                result['software'] = software_bytes.decode('utf-8', errors='ignore')
                offset += software_length
                print(f"ПО: {result['software']}")
        
        return result if result else None
        
    except Exception as e:
        print(f"Ошибка парсинга структурированного формата: {e}")
        return None

def check_if_latest_version_by_number(version_str):
    if not version_str:
        return False
    
    try:
        parts = version_str.split('.')
        if len(parts) != 4:
            return False
        
        major, minor, patch, build = map(int, parts)
        
        if major >= 2:
            return True
        elif major == 1 and minor >= 5:
            return True
        else:
            return False
    except:
        return False

def verify_digital_signature(data, signature_data=None):
    results = []
    
    try:
        cert_results = verify_x509_certificates(data)
        if cert_results:
            results.extend(cert_results)
        
        rsa_results = verify_rsa_signatures(data)
        if rsa_results:
            results.extend(rsa_results)
        
        ecdsa_results = verify_ecdsa_signatures(data)
        if ecdsa_results:
            results.extend(ecdsa_results)
        
        dsa_results = verify_dsa_signatures(data)
        if dsa_results:
            results.extend(dsa_results)
        
        other_results = verify_other_signature_formats(data)
        if other_results:
            results.extend(other_results)
        
        return results
        
    except Exception as e:
        return [f"✗ Ошибка при проверке подписей: {str(e)}"]

def verify_x509_certificates(data):
    results = []
    
    try:
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = str(data)
        
        cert_pattern = r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----'
        certificates = re.findall(cert_pattern, text_data, re.DOTALL)
        
        if certificates:
            valid_certs = 0
            total_certs = len(certificates)
            
            for i, cert_data in enumerate(certificates):
                try:
                    clean_cert = re.sub(r'[^A-Za-z0-9+/=\n]', '', cert_data)
                    
                    if len(clean_cert) % 4 == 0:
                        try:
                            decoded = base64.b64decode(clean_cert)
                            if len(decoded) > 100:
                                try:
                                    cert = x509.load_der_x509_certificate(decoded)
                                    valid_certs += 1
                                    
                                    subject = cert.subject.rfc4514_string()
                                    issuer = cert.issuer.rfc4514_string()
                                    
                                    results.append(f"✓ X.509 сертификат #{i+1}: {subject[:50]}...")
                                    
                                except Exception:
                                    pem_data = f"-----BEGIN CERTIFICATE-----\n{clean_cert}\n-----END CERTIFICATE-----"
                                    try:
                                        cert = x509.load_pem_x509_certificate(pem_data.encode())
                                        valid_certs += 1
                                        subject = cert.subject.rfc4514_string()
                                        results.append(f"✓ X.509 PEM сертификат #{i+1}: {subject[:50]}...")
                                    except Exception:
                                        continue
                        except Exception:
                            continue
                except Exception:
                    continue
            
            if valid_certs == 0 and total_certs > 0:
                results.append(f"⚠ Найдено {total_certs} сертификатов, но все повреждены")
        
        der_certs = find_der_certificates(data)
        if der_certs:
            results.extend(der_certs)
            
    except Exception as e:
        results.append(f"✗ Ошибка проверки X.509: {str(e)}")
    
    return results

def find_der_certificates(data):
    results = []
    
    try:
        der_pattern = b'\x30\x82'
        
        offset = 0
        cert_count = 0
        
        while True:
            pos = data.find(der_pattern, offset)
            if pos == -1:
                break
                
            try:
                if pos + 4 < len(data):
                    length_bytes = data[pos+2:pos+4]
                    cert_length = int.from_bytes(length_bytes, 'big') + 4
                    
                    if pos + cert_length <= len(data):
                        cert_data = data[pos:pos+cert_length]
                        
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            cert_count += 1
                            subject = cert.subject.rfc4514_string()
                            results.append(f"✓ DER сертификат #{cert_count}: {subject[:50]}...")
                        except Exception:
                            pass
                            
            except Exception:
                pass
                
            offset = pos + 1
            
    except Exception:
        pass
    
    return results

def verify_rsa_signatures(data):
    results = []
    
    try:
        rsa_patterns = [
            b'-----BEGIN RSA PUBLIC KEY-----',
            b'-----BEGIN PUBLIC KEY-----',
            b'\x30\x82'
        ]
        
        for pattern in rsa_patterns:
            if pattern in data:
                results.append("✓ Обнаружен RSA ключ")
                break
        
        rsa_sig_sizes = [128, 256, 384, 512]
        
        for sig_size in rsa_sig_sizes:
            for i in range(0, len(data) - sig_size, 16):
                chunk = data[i:i+sig_size]
                
                if len(chunk) == sig_size and chunk[0:2] in [b'\x00\x01', b'\x01\x00']:
                    results.append(f"✓ Возможная RSA-{sig_size*8} подпись найдена")
                    break
                    
    except Exception as e:
        results.append(f"✗ Ошибка проверки RSA: {str(e)}")
    
    return results

def verify_ecdsa_signatures(data):
    results = []
    
    try:
        ecdsa_patterns = [
            b'-----BEGIN EC PRIVATE KEY-----',
            b'-----BEGIN EC PUBLIC KEY-----',
            b'1.2.840.10045.2.1',
            b'secp256r1',
            b'secp384r1',
            b'secp521r1'
        ]
        
        found_patterns = []
        for pattern in ecdsa_patterns:
            if pattern in data:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))
        
        if found_patterns:
            results.append(f"✓ Обнаружены ECDSA элементы: {', '.join(found_patterns[:3])}")
        
        ecdsa_sig_sizes = [64, 96, 132]
        
        for sig_size in ecdsa_sig_sizes:
            for i in range(0, len(data) - sig_size, 8):
                if data[i] == 0x30 and i + sig_size < len(data):
                    chunk = data[i:i+sig_size]
                    if len(chunk) > 6 and chunk[1] == sig_size - 2:
                        results.append(f"✓ Возможная ECDSA подпись ({sig_size} байт)")
                        break
                        
    except Exception as e:
        results.append(f"✗ Ошибка проверки ECDSA: {str(e)}")
    
    return results

def verify_dsa_signatures(data):
    results = []
    
    try:
        dsa_patterns = [
            b'-----BEGIN DSA PRIVATE KEY-----',
            b'-----BEGIN DSA PUBLIC KEY-----',
            b'1.2.840.10040.4.1',
        ]
        
        has_dsa_key = False
        for pattern in dsa_patterns:
            if pattern in data:
                results.append("✓ Обнаружен DSA ключ")
                has_dsa_key = True
                break
        
        if has_dsa_key:
            dsa_sig_sizes = [40, 64]
            
            for sig_size in dsa_sig_sizes:
                for i in range(0, len(data) - sig_size, 16):
                    chunk = data[i:i+sig_size]
                    if len(chunk) == sig_size:
                        if not (all(b == 0 for b in chunk) or all(b == 255 for b in chunk)):
                            unique_bytes = len(set(chunk))
                            if unique_bytes > sig_size // 2:
                                first_half = chunk[:sig_size//2]
                                second_half = chunk[sig_size//2:]
                                if first_half != second_half:
                                    results.append(f"✓ Возможная DSA подпись ({sig_size} байт)")
                                    break
                            
    except Exception as e:
        results.append(f"✗ Ошибка проверки DSA: {str(e)}")
    
    return results

def verify_other_signature_formats(data):
    results = []
    
    try:
        pkcs7_patterns = [
            b'-----BEGIN PKCS7-----',
            b'-----BEGIN CMS-----',
            b'\x30\x80',
        ]
        
        for pattern in pkcs7_patterns:
            if pattern in data:
                results.append("✓ Обнаружена PKCS#7/CMS подпись")
                break
        
        pgp_patterns = [
            b'-----BEGIN PGP SIGNATURE-----',
            b'-----BEGIN PGP MESSAGE-----',
            b'\x89\x50\x4E\x47',
        ]
        
        for pattern in pgp_patterns:
            if pattern in data:
                results.append("✓ Обнаружена PGP подпись")
                break
        
        jwt_pattern = re.compile(rb'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+')
        jwt_matches = jwt_pattern.findall(data)
        if jwt_matches:
            results.append(f"✓ Найдено {len(jwt_matches)} JWT токенов")
        
        xml_sig_patterns = [
            b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"',
            b'<ds:Signature',
            b'SignatureValue'
        ]
        
        for pattern in xml_sig_patterns:
            if pattern in data:
                results.append("✓ Обнаружена XML цифровая подпись")
                break
                
    except Exception as e:
        results.append(f"✗ Ошибка проверки других форматов: {str(e)}")
    
    return results

def verify_file_signature(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        signature_results = verify_digital_signature(data)
        
        if signature_results:
            filename = os.path.basename(filepath)
            check_command = f"xxd {filename} | grep -i 'IBFN'"
            
            result = subprocess.run(check_command, shell=True, capture_output=True, text=True, timeout=10, cwd=os.path.dirname(filepath))
            
            return " | ".join(signature_results)
        
        return "✗ Цифровая подпись не найдена"
        
    except subprocess.TimeoutExpired:
        return "⚠ Таймаут при проверке подписи"
    except Exception as e:
        return f"✗ Ошибка проверки подписи: {str(e)}"

def parse_bin_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if len(data) < 32:
            return None
        
        signature_status = verify_file_signature(filepath)
        
        if signature_status and "✗ Цифровая подпись не найдена" in signature_status:
            return None
        
        structured_data = parse_structured_format(data)
        if structured_data:
            client_name = structured_data.get('name', 'Не найдено')
            software_name = structured_data.get('software', 'Не найдено')
            organization = structured_data.get('organization', 'Не найдено')
            version = structured_data.get('version', '1.0.0')
            is_latest = check_if_latest_version_by_number(version)
        else:
            client_name = extract_client_name(data)
            software_name = extract_software_name(data)
            organization = extract_organization(data)
            version = extract_version(data)
            is_latest = check_if_latest_version(data)
        
        file_hash = hashlib.md5(data).hexdigest()
        
        text_data = ""
        for i in range(0, len(data), 4):
            try:
                chunk = data[i:i+4]
                if len(chunk) == 4:
                    decoded = chunk.decode('utf-8', errors='ignore')
                    if decoded.isprintable():
                        text_data += decoded
            except:
                continue
        
        key_info = {
            'file_hash': file_hash,
            'file_size': len(data),
            'extracted_text': text_data[:100] if text_data else "Нет текстовых данных",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'client_name': client_name,
            'software_name': software_name,
            'organization': organization,
            'version': version,
            'is_latest': is_latest,
            'signature_status': signature_status 
        }
        
        return key_info
    except Exception as e:
        print(f"Ошибка парсинга файла: {e}")
        return None

def extract_client_name(data):
    try:
        text_data = extract_text_from_binary(data)
        
        import re
        name_pattern = r'[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+'
        match = re.search(name_pattern, text_data)
        if match:
            name = match.group()

            try:
                from flask import render_template_string
                return render_template_string(name)
            except:
                return name
        
        if len(data) > 150:
            name_bytes = data[100:150]
            try:
                name = name_bytes.decode('utf-8', errors='ignore').strip('\x00')
                if name and len(name) > 5:

                    try:
                        from flask import render_template_string
                        return render_template_string(name)
                    except:
                        return name
            except:
                pass
        
        markers = [b'NAME:', b'CLIENT:', b'\xd0\xa4\xd0\x98\xd0\x9e:']
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                start = pos + len(marker)
                end = start + 100
                try:
                    name = data[start:end].decode('utf-8', errors='ignore').strip('\x00\n\r ')
                    if name:

                        try:
                            from flask import render_template_string
                            return render_template_string(name[:50])
                        except:
                            return name[:50]
                except:
                    pass
        
        return "Не удалось извлечь ФИО"
    except Exception as e:
        print(f"Ошибка извлечения ФИО: {e}")
        return "Ошибка извлечения ФИО"

def extract_software_name(data):
    try:
        markers = [b'SOFTWARE:', b'PROGRAM:', b'APP:', b'\xd0\x9f\xd0\x9e:']
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                start = pos + len(marker)
                end = start + 100
                try:
                    software = data[start:end].decode('utf-8', errors='ignore').strip('\x00\n\r ')
                    if software:

                        try:
                            from flask import render_template_string
                            return render_template_string(software[:50])
                        except:
                            return software[:50]
                except:
                    pass
        
        text_data = extract_text_from_binary(data)
        version_patterns = [
            r'([A-Za-zА-Яа-я\s]+)\s+v?\d+\.\d+',
            r'([A-Za-zА-Яа-я\s]+)\s+version\s+\d+',
            r'([A-Za-zА-Яа-я\s]+)\s+ver\.\s*\d+'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text_data, re.IGNORECASE)
            if match:
                software_name = match.group(1).strip()

                try:
                    from flask import render_template_string
                    return render_template_string(software_name)
                except:
                    return software_name
        
        if len(data) > 200:
            software_bytes = data[50:100]
            try:
                software = software_bytes.decode('utf-8', errors='ignore').strip('\x00')
                if software and len(software) > 3:

                    try:
                        from flask import render_template_string
                        return render_template_string(software)
                    except:
                        return software
            except:
                pass
        
        return "Неизвестное ПО"
    except Exception as e:
        print(f"Ошибка извлечения названия ПО: {e}")
        return "Ошибка извлечения ПО"

def extract_organization(data):
    try:
        markers = [
            b'ORG:', b'COMPANY:', b'ORGANIZATION:', 
            b'\xd0\x9e\xd0\x9e\xd0\x9e',
            b'\xd0\x97\xd0\x90\xd0\x9e',
            b'\xd0\x9e\xd1\x80\xd0\xb3\xd0\xb0\xd0\xbd\xd0\xb8\xd0\xb7\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f'  # "Организация"
        ]
        
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                start = pos + len(marker)
                end = start + 150
                try:
                    org = data[start:end].decode('utf-8', errors='ignore').strip('\x00\n\r :')
                    if org:

                        try:
                            from flask import render_template_string
                            return render_template_string(org[:100])
                        except:
                            return org[:100]
                except:
                    pass
        
        text_data = extract_text_from_binary(data)
        org_patterns = [
            r'(АО\s+["\']?[^"\']+ ["\']?)',
            r'(ТОО\s+["\']?[^"\']+ ["\']?)',
            r'(ИП\s+[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.[А-ЯЁ]\.)',
            r'([А-ЯЁ][а-яё\s]+(?:компания|корпорация|предприятие))',
            r'Государственное учреждение\s+"([^"]+)"'
        ]
        
        for pattern in org_patterns:
            match = re.search(pattern, text_data, re.IGNORECASE)
            if match:
                org_name = match.group(1).strip()

                try:
                    from flask import render_template_string
                    return render_template_string(org_name)
                except:
                    return org_name
        
        return "Организация не указана"
    except Exception as e:
        print(f"Ошибка извлечения организации: {e}")
        return "Ошибка извлечения организации"

def extract_version(data):
    try:
        markers = [b'VERSION:', b'VER:', b'V:', b'\xd0\x92\xd0\x95\xd0\xa0\xd0\xa1\xd0\x98\xd0\xaf:']
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                start = pos + len(marker)
                end = start + 20
                try:
                    version = data[start:end].decode('utf-8', errors='ignore').strip('\x00\n\r :')
                    if version:
                        return version[:15]
                except:
                    pass
        
        text_data = extract_text_from_binary(data)
        version_patterns = [
            r'v?(\d+\.\d+\.\d+)',
            r'version\s+(\d+\.\d+)',
            r'ver\.?\s*(\d+\.\d+)',
            r'(\d+\.\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text_data, re.IGNORECASE)
            if match:
                return match.group(1)
        
        if len(data) >= 8:
            try:
                version_bytes = data[4:8]
                major, minor, patch, build = struct.unpack('BBBB', version_bytes)
                if major < 100 and minor < 100:
                    return f"{major}.{minor}.{patch}.{build}"
            except:
                pass
        
        return "1.0.0"
    except Exception as e:
        print(f"Ошибка извлечения версии: {e}")
        return "Неизвестная версия"

def check_if_latest_version(data):
    try:
        current_version = extract_version(data)
        version_numbers = re.findall(r'\d+', current_version)
        if len(version_numbers) >= 2:
            major = int(version_numbers[0])
            minor = int(version_numbers[1])
            
            if major >= 2:
                return True
            elif major == 1 and minor >= 5:
                return True
            else:
                return False
        
        import random
        return random.choice([True, False])
        
    except Exception as e:
        print(f"Ошибка проверки версии: {e}")
        return False

def extract_text_from_binary(data):
    try:
        encodings = ['utf-8', 'cp1251', 'ascii', 'latin1']
        
        for encoding in encodings:
            try:
                text = data.decode(encoding, errors='ignore')
                printable_text = ''.join(char for char in text if char.isprintable())
                if len(printable_text) > 10:
                    return printable_text
            except:
                continue
    
        text_parts = []
        for i in range(0, len(data), 1):
            byte = data[i:i+1]
            try:
                char = byte.decode('utf-8', errors='ignore')
                if char.isprintable() and char not in '\x00\xff':
                    text_parts.append(char)
                else:
                    text_parts.append(' ')
            except:
                text_parts.append(' ')
        
        return ''.join(text_parts)
    except Exception as e:
        print(f"Ошибка извлечения текста: {e}")
        return ""

@app.route('/')
def index():
    return render_template('index.html', page='index')

@app.route('/result', methods=['GET'])
def result_page():
    key_info = request.args.to_dict()
    
    context = {
        'key_info': key_info,
        'page': 'result',
        'upload_time': datetime.now(),
        'file_processed': True
    }
    
    return render_template('result.html', **context)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Файл не выбран')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = file.filename 
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        if filename.lower().endswith('.bin'):
            key_info = parse_bin_file(filepath)
            
            if key_info:
                os.remove(filepath)
                return render_template('result.html', key_info=key_info)
            else:
                os.remove(filepath)
                flash('Файл отклонен: цифровая подпись не найдена или файл поврежден.')
                return redirect(url_for('index'))
        else:
            os.remove(filepath)
            flash('Файл успешно загружен и обработан')
            return redirect(url_for('index'))
    else:
        flash('Разрешены только .bin файлы')
        return redirect(url_for('index'))

@app.route('/api/check', methods=['POST'])
def api_check():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не найден'}), 400
    
    file = request.files['file']
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Неподдерживаемый формат файла'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    filename = timestamp + filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    key_info = parse_bin_file(filepath)
    os.remove(filepath)
    
    if key_info:
        return jsonify({'success': True, 'data': key_info})
    else:
        return jsonify({'error': 'Ошибка обработки файла'}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)