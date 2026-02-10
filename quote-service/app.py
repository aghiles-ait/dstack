from flask import Flask, jsonify, request
from dstack_sdk import DstackClient

app = Flask(__name__)
client = DstackClient()

@app.route('/attestation')
def get_attestation():
    # Get report_data from query parameter, must start with 0x and be hexadecimal
    report_data_param = request.args.get('report_data')
    
    if not report_data_param:
        # Default to 64 bytes of zeros
        report_data_hex = '0' * 128
    else:
        # Remove 0x prefix if present
        if report_data_param.startswith('0x') or report_data_param.startswith('0X'):
            report_data_hex = report_data_param[2:]
        else:
            return jsonify({'error': 'report_data must start with 0x prefix'}), 400
        
        # Validate hexadecimal format
        try:
            int(report_data_hex, 16)
        except ValueError:
            return jsonify({'error': 'report_data must be a valid hexadecimal string'}), 400
    
    try:
        report_data = bytes.fromhex(report_data_hex)
        # Pad with zeros to reach 64 bytes if smaller
        if len(report_data) > 64:
            return jsonify({'error': 'report_data must be at most 64 bytes (128 hex characters after 0x)'}), 400
        elif len(report_data) < 64:
            # Pad with zeros on the right
            report_data = report_data + b'\x00' * (64 - len(report_data))
    except ValueError:
        return jsonify({'error': 'Invalid report_data format. Must be hexadecimal string'}), 400
    
    result = client.get_quote(report_data)
    return jsonify({
        'quote': result.quote,
        'event_log': result.event_log,
        'vm_config': result.vm_config  # Required by dstack-verifier
    })

@app.route('/info')
def get_info():
    info = client.info()
    # Convert InfoResponse Pydantic model to dict for JSON serialization
    # Try model_dump() first (Pydantic v2), then model_dump_json() or dict()
    if hasattr(info, 'model_dump'):
        return jsonify(info.model_dump())
    elif hasattr(info, 'dict'):
        return jsonify(info.dict())
    else:
        # Fallback: use vars() which should work for BaseModel
        return jsonify(vars(info))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)