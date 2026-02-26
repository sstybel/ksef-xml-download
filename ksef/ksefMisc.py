import os
import json
import datetime

ksefSubjectTypeLabels = {
    "Subject1and2": "issued (sales) and received (purchases) - Subject1 and Subject2",
    "Subject1": "issued (sales) - Subject1",
    "Subject2": "received (purchases) - Subject2"
}

def print_line():
    print("--------------------------------------------------------------------\n")

def print_app_title(app_name, app_author):
    print(f"\n{app_name}")
    print(f"{app_author}")
    print_line()

def format_amount(amount) -> str:
    if amount is None:
        return "N/A"
    try:
        return f"{float(amount):.2f}"
    except (ValueError, TypeError):
        return str(amount)

def format_amount_csv(amount) -> str:
    val = format_amount(amount)
    return str(val).replace('.', ',')
    
def create_filename(filename, path=".\\", prefix_filename="ksef", fileextension=".json"):
    str_timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    new_filename = f"{prefix_filename}_{filename}_{str_timestamp}{fileextension}"
    filepath = os.path.join(path, f"{new_filename}")
    filepath = filepath.replace('/', f"\\")
    filepath = filepath.replace(f"\\.\\", f".\\")

    return filepath

def print_invoices_table(invoices_dict: dict = {}, output_path=".\\"):
    tab_output_filename = create_filename("invoices-output-table", path=output_path, prefix_filename="ksef", fileextension=".txt")  

    if not invoices_dict:
        print("No invoices found.")
        return

    with open(tab_output_filename, 'w', encoding='utf-8') as tab_file:
        print("\n" + "=" * 140)
        print(f"{'KSeF subject':<20} {'KSeF number':<45} {'Invoice number':<20} {'Date':<12} {'Sales tax ID (NIP)':<12} {'Gross amount':>15}")
        print("=" * 140)
        tab_file.write("=" * 140 + "\n")
        tab_file.write(f"{'KSeF subject':<20} {'KSeF number':<45} {'Invoice number':<20} {'Date':<12} {'Sales tax ID (NIP)':<12} {'Gross amount':>15}\n")
        tab_file.write("=" * 140 + "\n")

        for inv_dict in invoices_dict:
            invoices = invoices_dict[inv_dict]
            for inv in invoices:
                ksef_subtype = inv_dict
                ksef_num = inv.get('ksefNumber', 'N/A')[:44]
                inv_num = inv.get('invoiceNumber', 'N/A')[:19]
                inv_date = inv.get('issueDate', 'N/A')[:11]

                seller = inv.get('seller', {})
                seller_nip = seller.get('nip', 'N/A') if isinstance(seller, dict) else 'N/A'

                gross = format_amount(inv.get('grossAmount'))

                print(f"{ksef_subtype:<20} {ksef_num:<45} {inv_num:<20} {inv_date:<12} {seller_nip:<12} {gross:>15}")
                tab_file.write(f"{ksef_subtype:<20} {ksef_num:<45} {inv_num:<20} {inv_date:<12} {seller_nip:<12} {gross:>15}\n")

        print("=" * 140)
        print(f"Total: {len(invoices)} invoice(s)")
        tab_file.write("=" * 140 + "\n")
        tab_file.write(f"Total: {len(invoices)} invoice(s)\n")

def print_invoices_csv(invoices_dict: dict = {}, output_path=".\\", xml_sub1_output_path=".\\", xml_sub2_output_path=".\\"):
    csv_output_filename = create_filename("invoices-output-csv", path=output_path, prefix_filename="ksef", fileextension=".csv")  

    if not invoices_dict:
        print("No invoices found.")
        return

    with open(csv_output_filename, 'w', encoding='windows-1250') as csv_file:
        csv_header = f"\"ksefSubjectType\";\"ksefNumber\";\"formSystemCode\";\"formSchemaVersion\";\"formValue\";\"invoiceNumber\";\"invoiceIssueDate\";\"invoiceCurrency\";\"invoiceType\";\"invoicingMode\";\"invoiceHash\";\"sellerNIP\";\"sellerName\";\"buyerIdType\";\"buyerIdValue\";\"buyerName\";\"netAmount\";\"vatAmount\";\"grossAmount\";\"qrCode\";\"fileName\"" 
        print(csv_header)
        csv_file.write(csv_header + "\n")

        for inv_dict in invoices_dict:
            invoices = invoices_dict[inv_dict]
            for inv in invoices:
                ksef_subtype = inv_dict
                ksef_num = inv.get('ksefNumber', 'N/A')[:44]

                if ksef_subtype == "Subject1":
                    xml_path = xml_sub1_output_path
                elif ksef_subtype == "Subject2":
                    xml_path = xml_sub2_output_path
                xml_output_dir = xml_path
                xml_output_dir = str(xml_output_dir).replace('/', f"\\")
                xml_output_dir = xml_output_dir.replace(f"\\.\\", f".\\")

                form_code = inv.get('formCode', {})
                form_scode = form_code.get('systemCode', 'N/A') if isinstance(form_code, dict) else 'N/A'
                form_ver = form_code.get('schemaVersion', 'N/A') if isinstance(form_code, dict) else 'N/A'
                form_val = form_code.get('value', 'N/A') if isinstance(form_code, dict) else 'N/A'

                inv_num = inv.get('invoiceNumber', 'N/A')[:19]
                inv_date = inv.get('issueDate', 'N/A')[:11]
                inv_curr = inv.get('currency', 'N/A')
                inv_type = inv.get('invoiceType', 'N/A')
                inv_mode = inv.get('invoicingMode', 'N/A')
                inv_hash = inv.get('invoiceHash', 'N/A')

                seller = inv.get('seller', {})
                seller_nip = seller.get('nip', 'N/A') if isinstance(seller, dict) else 'N/A'
                seller_name = seller.get('name', 'N/A') if isinstance(seller, dict) else 'N/A'

                buyer = inv.get('buyer', {})
                buyer_id = buyer.get('identifier', {})
                buyer_val = buyer_id.get('value', 'N/A') if isinstance(buyer_id, dict) else 'N/A'
                buyer_type = buyer_id.get('type', 'N/A') if isinstance(buyer_id, dict) else 'N/A'
                buyer_name = buyer.get('name', 'N/A') if isinstance(buyer, dict) else 'N/A'

                gross = format_amount_csv(inv.get('grossAmount'))
                net = format_amount_csv(inv.get('netAmount'))
                vat = format_amount_csv(inv.get('vatAmount'))

                ksef_num_spl = ksef_num.split('-')
                qrCodeData = str(ksef_num_spl[1])
                qrCodeData = qrCodeData[6:8]  + "-" + qrCodeData[4:6]  + "-" + qrCodeData[0:4]
                grHash = str(inv_hash).split('=')[0]
                grHash = grHash.replace('+', '-')
                grHash = grHash.replace('/', '_')
                qrCode = 'https://qr.ksef.mf.gov.pl/invoice/' + ksef_num_spl[0] + '/' + qrCodeData + '/' + grHash
                fileName = f"{ksef_num}.xml"
                fileName= fileName.replace('/', '_').replace(f"\\", '_')
                fileName = os.path.join(xml_output_dir, f"{fileName}")
                fileName = fileName.replace('/', f"\\")
                fileName = fileName.replace(f"\\.\\", f".\\")
    
                csv_record = ""
                csv_record = csv_record + f"\"{ksef_subtype}\";\"{ksef_num}\";\"{form_scode}\";\"{form_ver}\";\"{form_val}\";\"{inv_num}\";\"{inv_date}\";\"{inv_curr}\";\"{inv_type}\";\"{inv_mode}\";\"{inv_hash}\";\"{seller_nip}\";\"{seller_name}\";\"{buyer_type}\";\"{buyer_val}\";\"{buyer_name}\";\"{net}\";\"{vat}\";\"{gross}\";\"{qrCode}\";\"{fileName}\""
            
                print(csv_record.strip())
                csv_file.write(csv_record.strip() + "\n")

def print_invoices_json(invoices_dict: dict = {}, output_path=".\\", xml_sub1_output_path=".\\", xml_sub2_output_path=".\\"):
    _invoices = {}
    for subject_type, invoices in invoices_dict.items():
        _invoices[subject_type] = invoices.copy()

    for inv_sub in invoices_dict:
        inv = invoices_dict[inv_sub]
        inv_rec_num = 0
        for inv_rec in inv:
            if inv_sub == "Subject1":
                xml_path = xml_sub1_output_path
            elif inv_sub == "Subject2":
                xml_path = xml_sub2_output_path
            xml_output_dir = xml_path
            xml_output_dir = str(xml_output_dir).replace('/', f"\\")
            xml_output_dir = xml_output_dir.replace(f"\\.\\", f".\\")
            
            ksef_num = inv_rec.get('ksefNumber', 'N/A')[:44]
            inv_hash = inv_rec.get('invoiceHash', 'N/A')
            ksef_num_spl = ksef_num.split('-')
            qrCodeData = str(ksef_num_spl[1])
            qrCodeData = qrCodeData[6:8]  + "-" + qrCodeData[4:6]  + "-" + qrCodeData[0:4]
            grHash = str(inv_hash).split('=')[0]
            grHash = grHash.replace('+', '-')
            grHash = grHash.replace('/', '_')
            qrCode = 'https://qr.ksef.mf.gov.pl/invoice/' + ksef_num_spl[0] + '/' + qrCodeData + '/' + grHash
            fileName = f"{ksef_num}.xml"
            fileName= fileName.replace('/', '_').replace(f"\\", '_')
            fileName = os.path.join(xml_output_dir, f"{fileName}")
            fileName = fileName.replace('/', f"\\")
            fileName = fileName.replace(f"\\.\\", f".\\")
            _invoices[inv_sub][inv_rec_num].update({"qrCode": qrCode})
            _invoices[inv_sub][inv_rec_num].update({"fileName": fileName})
            inv_rec_num += 1

    print(json.dumps(_invoices, indent=4, ensure_ascii=False, default=str))

    json_output_filename = create_filename("invoices-output-json", path=output_path, prefix_filename="ksef", fileextension=".json")  

    with open(json_output_filename, 'w', encoding='utf-8') as json_file:
        json.dump(_invoices, json_file, ensure_ascii=False, indent=4)

def ksef_CheckState(state_dir = ".\\", xml_sub1_output_dir = ".\\", xml_sub2_output_dir = ".\\", invoices_dict: dict = {}) -> dict:

    state_file_path = os.path.join(state_dir, 'ksef_state.json')
    state_file_path = state_file_path.replace('/', f"\\")
    state_file_path = state_file_path.replace(f"\\.\\", f".\\")

    _invoices_dict = {}
    for subject_type, invoices in invoices_dict.items():
        _invoices_dict[subject_type] = invoices.copy()

    try:
        with open(state_file_path, 'r', encoding='utf-8') as state_file:
            state_data = json.load(state_file)
        print(f"KSeF state loaded from: {state_file_path}")
    except FileNotFoundError:
        print(f"No existing KSeF state found at: {state_file_path}. A new state file will be created at: {state_file_path}")
        state_data = {}

    for subject_type, invoices in invoices_dict.items():
        for invoice in invoices:
            ksef_number = invoice.get('ksefNumber')
            if ksef_number:
                ksef_idx = f"{subject_type}_{ksef_number}"
                if ksef_idx in state_data:
                    invHash = invoice['invoiceHash']
                    stateInvHash = state_data[ksef_idx].get('Hash')
                    idx = _invoices_dict[subject_type].index(invoice)
                    if (invHash == stateInvHash) and (idx >= 0):
                        del _invoices_dict[subject_type][idx]
                else:
                    if subject_type == "Subject1":
                        xml_output_dir = xml_sub1_output_dir
                    elif subject_type == "Subject2":
                        xml_output_dir = xml_sub2_output_dir
                    safe_name = ksef_number.replace('/', '_').replace(f"\\", '_')
                    xmlfilepath = os.path.join(xml_output_dir, f"{safe_name}.xml")
                    xmlfilepath = xmlfilepath.replace('/', f"\\")
                    xmlfilepath = xmlfilepath.replace(f"\\.\\", f".\\")
                    state_ksef = {"ksefNumber": ksef_number, "SubjectType": subject_type, "Hash": invoice['invoiceHash'], "IssueDate": invoice['issueDate'], "xmlFilePath": xmlfilepath}
                    state_data.update({ksef_idx: state_ksef})

    os.makedirs(state_dir, exist_ok=True)
    with open(state_file_path, 'w', encoding='utf-8') as state_file:
        json.dump(state_data, state_file, ensure_ascii=False, indent=4)
    print(f"KSeF state saved to: {state_file_path}")

    return _invoices_dict
