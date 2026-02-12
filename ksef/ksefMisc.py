import json
import datetime

ksefSubjectTypeLabels = {
    "Subject1&2": "issued (sales) & received (purchases) - Subject1 & Subject2",
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
    
def create_filename(filename, path=".\\t", prefix_filename="ksef", fileextension=".json"):
    str_timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    return f"{path}{prefix_filename}_{filename}_{str_timestamp}{fileextension}"

def print_invoices_table(invoices_dict: dict):
    tab_output_filename = create_filename("invoices-output-table", path=".\\", prefix_filename="ksef", fileextension=".txt")  

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

def print_invoices_csv(invoices_dict: dict):
    csv_output_filename = create_filename("invoices-output-csv", path=".\\", prefix_filename="ksef", fileextension=".csv")  

    if not invoices_dict:
        print("No invoices found.")
        return

    with open(csv_output_filename, 'w', encoding='utf-8') as csv_file:
        csv_header = f"\"ksefSubjectType\";\"ksefNumber\";\"formSystemCode\";\"formSchemaVersion\";\"formValue\";\"invoiceNumber\";\"invoiceIssueDate\";\"invoiceCurrency\";\"invoiceType\";\"invoicingMode\";\"invoiceHash\";\"sellerNIP\";\"sellerName\";\"buyerIdType\";\"buyerIdValue\";\"buyerName\";\"netAmount\";\"vatAmount\";\"grossAmount\"" 
        print(csv_header)
        csv_file.write(csv_header + "\n")

        for inv_dict in invoices_dict:
            invoices = invoices_dict[inv_dict]
            for inv in invoices:
                ksef_subtype = inv_dict
                ksef_num = inv.get('ksefNumber', 'N/A')[:44]

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

                csv_record = ""
                csv_record = csv_record + f"\"{ksef_subtype}\";\"{ksef_num}\";\"{form_scode}\";\"{form_ver}\";\"{form_val}\";\"{inv_num}\";\"{inv_date}\";\"{inv_curr}\";\"{inv_type}\";\"{inv_mode}\";\"{inv_hash}\";\"{seller_nip}\";\"{seller_name}\";\"{buyer_type}\";\"{buyer_val}\";\"{buyer_name}\";\"{net}\";\"{vat}\";\"{gross}\""
            
                print(csv_record.strip())
                csv_file.write(csv_record.strip() + "\n")

def print_invoices_json(invoices: dict):
    print(json.dumps(invoices, indent=4, ensure_ascii=False, default=str))

    json_output_filename = create_filename("invoices-output-json", path=".\\", prefix_filename="ksef", fileextension=".json")  

    with open(json_output_filename, 'w', encoding='utf-8') as json_file:
        json.dump(invoices, json_file, ensure_ascii=False, indent=4)
