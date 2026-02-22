import os
import sys
import json
import logging
import argparse
import datetime

from ksef import ksefMisc
from ksef import ksefError
from ksef import ksefClient

str_version = "1.00"
str_app_name ="KSeF XML Invoices Downloader - ver. " + str_version
str_author = "Copyright (c) 2025 - 2026 by Sebastian Stybel, www.BONO-IT.pl"

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description='Download invoices from National e-Invoice System - KSeF (Krajowy System e-Faktur)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
    # Certificate authentication (XAdES) to KSeF system - requires nip (Tax ID), cert, key, and password
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password secret
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password-file pass.txt

    # Token authentication to KSeF system - requires nip (Tax ID), token
    %(prog)s --nip 1234567890 --token "your-ksef-token"
    %(prog)s --nip 1234567890 --token-file token.txt

    # With options
    %(prog)s --nip 1234567890 --token-file token.txt --env prod --date-from 2026-02-01
    %(prog)s --nip 1234567890 --token-file token.txt --env prod --subject-type Subject1
                         --output json --xml-output-dir .\\invoices-sales\\
    %(prog)s --nip 1234567890 --token-file token.txt --env prod --ksef-state-dir d:\\_test-ksef_\\state\\
                         --subject-type Subject1and2 --output json --output-dir d:\\_test-ksef_\\output\\ --download-xml
                         --xml-output-dir d:\\_test-ksef_\\invoices\\
        """
    )

    parser.add_argument('--nip', help='NIP (Tax ID) of the entity (required for KSeF queries)', required=(not(('--help' in sys.argv) or ('-h' in sys.argv))))

    auth_cert = parser.add_argument_group('Certificate authentication (XAdES)')
    auth_cert.add_argument('--cert', help='Path to certificate file (PEM)', required=(('--nip' in sys.argv) and not(('--token' in sys.argv) or ('--token-file' in sys.argv))))
    auth_cert.add_argument('--key', help='Path to private key file (PEM)', required=('--cert' in sys.argv))
    auth_cert.add_argument('--password', help='Password for encrypted private key', required=(('--cert' in sys.argv) and not('--password-file' in sys.argv)))
    auth_cert.add_argument('--password-file', help='File containing password for private key', required=(('--cert' in sys.argv) and not('--password' in sys.argv)))

    auth_token = parser.add_argument_group('Token authentication')
    auth_token.add_argument('--token', help='KSeF authorization token', required=(('--nip' in sys.argv) and not('--cert' in sys.argv) and not('--token-file' in sys.argv)))
    auth_token.add_argument('--token-file', help='File containing KSeF token', required=(('--nip' in sys.argv) and not('--cert' in sys.argv) and not('--token' in sys.argv)))

    parser.add_argument('--env', choices=['prod', 'test', 'demo'], default='prod',
                        help='KSeF environment (default: prod)')
    parser.add_argument('--date-from', help='Start date YYYY-MM-DD (default: 30 days ago)')
    parser.add_argument('--date-to', help='End date YYYY-MM-DD (default: today)')    
    parser.add_argument('--subject-type', choices=['Subject1', 'Subject2', 'Subject1and2'], default='Subject2',
                        help='Subject1=issued/sales, Subject2=received/purchases, Subject1and2=issued/sales and received/purchases (default subject type: Subject2)')
    parser.add_argument('--ksef-state-dir', default=None,
                        help='Path to the state file (ksef_state.json) for downloading invoices from the KSeF system. If not provided, the state will be stored in the current directory.')    
    parser.add_argument('--output', choices=['json', 'csv', 'table'], default='json',
                        help='Output format of results to display and save to file under the name according to the pattern ksef_invoices-output-[json | csv | txt]_YYYYMMDDhhmmss.[json | csv | txt] (default output format: json)')
    parser.add_argument('--output-dir', default=f".\\",
                        help='Directory to save output files (default: current directory)')   
    parser.add_argument('--download-xml', action='store_true',
                        help='Download full XML for each invoice')
    parser.add_argument('--xml-output-dir', default=f".\\",
                        help='Directory to save XML files (default: current directory)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--help', '-h', action='store_true',
                        help='Show this help message and exit')

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    use_token_auth = args.token or args.token_file
    use_cert_auth = args.cert or args.key

    ksefMisc.print_app_title(str_app_name, str_author)

    if not args.nip:
        print("ERR: --nip (Tax ID) is required for KSeF system queries", file=sys.stderr)
        sys.exit(1)

    if not use_token_auth and not use_cert_auth:
        print("ERR: You must provide a token (--token/--token-file) or certificate (--cert/--key).", file=sys.stderr)
        sys.exit(1)

    if use_token_auth and use_cert_auth:
        print("ERR: You cannot use both a token and a certificate at the same time. Choose one method.", file=sys.stderr)
        sys.exit(1)

    token = None
    if use_token_auth:
        token = args.token
        if not token and args.token_file:
            if not os.path.exists(args.token_file):
                print(f"ERR: Token file not found: {args.token_file}", file=sys.stderr)
                sys.exit(1)
            with open(args.token_file, 'r') as f:
                token = f.read().strip()
        if not token:
            print("ERR: Token is empty", file=sys.stderr)
            sys.exit(1)

    password = None
    if use_cert_auth:
        password = args.password
        if not password and args.password_file:
            if not os.path.exists(args.password_file):
                print(f"ERR: Password file not found: {args.password_file}", file=sys.stderr)
                sys.exit(1)
            with open(args.password_file, 'r') as f:
                password = f.read().strip()

        if not args.cert or not os.path.exists(args.cert):
            print(f"ERR: Certificate file not found: {args.cert}", file=sys.stderr)
            sys.exit(1)
        if not args.key or not os.path.exists(args.key):
            print(f"ERR: Private key file not found: {args.key}", file=sys.stderr)
            sys.exit(1)

    date_from = None
    date_to = None
    if args.date_from:
        try:
            date_from = datetime.datetime.strptime(args.date_from, '%Y-%m-%d').date()
        except ValueError:
            print(f"ERR: Invalid date format for --date-from: {args.date_from}", file=sys.stderr)
            sys.exit(1)
    if args.date_to:
        try:
            date_to = datetime.datetime.strptime(args.date_to, '%Y-%m-%d').date()
        except ValueError:
            print(f"ERR: Invalid date format for --date-to: {args.date_to}", file=sys.stderr)
            sys.exit(1)

    try:
        if use_token_auth:
            client = ksefClient.ksefClient(logger=logger).from_token(
                token=token,
                environment=args.env
            )
            auth_method = "token"
        else:
            client = ksefClient.ksefClient(logger=logger).from_certificate(
                cert_path=args.cert,
                key_path=args.key,
                key_password=password,
                environment=args.env
            )
            auth_method = "certificate (XAdES)"

        print(f"Connecting to KSeF system (environment: {args.env})...")
        print(f"NIP (Tax ID): {args.nip}")
        print(f"Authentication method: {auth_method}")

        if use_token_auth:
            session_info = client.init_session_token(args.nip)
        else:
            session_info = client.init_session_xades(args.nip)
        print(f"Session initialized. Reference number: {session_info['reference_number']}")

        subject_type = args.subject_type
        subject_type_label = ksefMisc.ksefSubjectTypeLabels[subject_type]

        print(f"\nDownloading invoices {subject_type_label}...")
        if date_from:
            print(f"Date range: {date_from} - {date_to or 'today'}")

        if (subject_type == "Subject1and2"):
            result = client.query_invoices(
                subject_type="Subject1",
                date_from=date_from,
                date_to=date_to
            )

            invSub1 = result.get('invoices', [])

            result = client.query_invoices(
                subject_type="Subject2",
                date_from=date_from,
                date_to=date_to
            )

            invSub2 = result.get('invoices', [])

            invoicesData = {f"Subject1": invSub1, f"Subject2": invSub2}
        else:
            result = client.query_invoices(
                subject_type=subject_type,
                date_from=date_from,
                date_to=date_to
            )

            invSubX = result.get('invoices', [])
            invoicesData = {f"{subject_type}": invSubX}

        if args.ksef_state_dir:
            invoicesData = ksefMisc.ksef_CheckState(state_dir=args.ksef_state_dir, xml_output_dir=args.xml_output_dir, invoices_dict=invoicesData)

        if args.output_dir:
            output_dir = str(args.output_dir)
            output_dir = str(output_dir).replace('/', f"\\")
            output_dir = output_dir.replace(f"\\.\\", f".\\")
            os.makedirs(output_dir, exist_ok=True)
        else:
            output_dir = f".\\"

        if args.output == 'json':
            ksefMisc.print_invoices_json(invoicesData, output_path=output_dir, xml_path=args.xml_output_dir)
        elif args.output == 'csv':
            ksefMisc.print_invoices_csv(invoicesData, output_path=output_dir, xml_path=args.xml_output_dir)
        else:
            ksefMisc.print_invoices_table(invoicesData, output_path=output_dir)

        xml_cache = {}

        def get_xml_cached(ksef_number):
            if ksef_number not in xml_cache:
                xml_cache[ksef_number] = client.get_invoice_xml(ksef_number)
            return xml_cache[ksef_number]

        for invoicesSub in invoicesData:
            invoices = invoicesData[invoicesSub]

            if args.download_xml and invoices:
                _xml_output_dir = args.xml_output_dir
                _xml_output_dir = str(_xml_output_dir).replace('/', f"\\")
                _xml_output_dir = _xml_output_dir.replace(f"\\.\\", f".\\")
                print(f"\nDownloading KSeF XML file(s) from {ksefMisc.ksefSubjectTypeLabels[invoicesSub]} to: {_xml_output_dir}")
                os.makedirs(_xml_output_dir, exist_ok=True)

                for inv in invoices:
                    ksef_number = inv.get('ksefNumber')
                    if ksef_number:
                        try:
                            xml_content = get_xml_cached(ksef_number)

                            safe_name = ksef_number.replace('/', '_').replace(f"\\", '_')
                            filepath = os.path.join(_xml_output_dir, f"{safe_name}.xml")
                            filepath = filepath.replace('/', f"\\")
                            filepath = filepath.replace(f"\\.\\", f".\\")
                            with open(filepath, 'w+', newline="\n", encoding='utf-8') as f:
                                f.write(xml_content)
                            print(f"  Downloaded: {filepath}")
                        except ksefError.ksefError as e:
                            print(f"  Error downloading {ksef_number}: {e.message}", file=sys.stderr)

        print("\nEnding session...")
        client.terminate_session()
        print("Session ended.")

    except ksefError.ksefError as e:
        print(f"\nERR-KSeF: {e.message}", file=sys.stderr)
        if e.response_data:
            print(f"ERR-KSeF-Details: {json.dumps(e.response_data, indent=2)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nERR-Unexpected: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
