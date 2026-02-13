import os
import sys
import json
import logging
import argparse
import datetime

from ksef import ksefMisc
from ksef import ksefError
from ksef import ksefClient
from ksef import ksefPDFGenerator

str_version = "1.00"
str_app_name ="KSeF XML Invoices Downloader - ver. " + str_version
str_author = "Copyright (c) 2025 - 2026 by Sebastian Stybel, www.BONO.Edu.PL"

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description='Download invoices from National e-Invoice System - KSeF (Krajowy System e-Faktur)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
    %(prog)s --nip 1234567890 --token-file token.txt --download-pdf --pdf-output-dir ./pdf

    # Offline conversation KSeF invoices of XML format to visualization invoices of PDF format (no authentication needed)
    %(prog)s --xml-to-pdf invoices.xml
    %(prog)s --xml-to-pdf ./invoices_xml/ --pdf-output-dir ./invoices_pdf/
        """
    )

    parser.add_argument('--nip', help='NIP (Tax ID) of the entity (required for KSeF queries)', required=True)

    offline_group = parser.add_argument_group('Offline XML to PDF conversion (no authentication needed)')
    offline_group.add_argument('--xml-to-pdf', metavar='PATH',
                               help='Convert XML file or directory of XML files to PDF (offline, no KSeF auth)')

    auth_cert = parser.add_argument_group('Certificate authentication (XAdES)')
    auth_cert.add_argument('--cert', help='Path to certificate file (PEM)', required=(('--nip' in sys.argv) and not(('--token' in sys.argv) or ('--token-file' in sys.argv))))
    auth_cert.add_argument('--key', help='Path to private key file (PEM)', required=('--cert' in sys.argv))
    auth_cert.add_argument('--password', help='Password for encrypted private key', required=(('--cert' in sys.argv) and not('--password-file' in sys.argv)))
    auth_cert.add_argument('--password-file', help='File containing password for private key', required=(('--cert' in sys.argv) and not('--password' in sys.argv)))

    auth_token = parser.add_argument_group('Token authentication')
    auth_token.add_argument('--token', help='KSeF authorization token', required=(('--nip' in sys.argv) and not('--cert' in sys.argv) and not('--token-file' in sys.argv)))
    auth_token.add_argument('--token-file', help='File containing KSeF token', required=(('--nip' in sys.argv) and not('--cert' in sys.argv) and not('--token' in sys.argv)))

    parser.add_argument('--env', choices=['test', 'demo', 'prod'], default='prod',
                        help='KSeF environment (default: prod)')
    parser.add_argument('--date-from', help='Start date YYYY-MM-DD (default: 30 days ago)')
    parser.add_argument('--date-to', help='End date YYYY-MM-DD (default: today)')
    parser.add_argument('--subject-type', choices=['Subject1', 'Subject2', 'Subject1&2'], default='Subject2',
                        help='Subject1=issued/sales, Subject2=received/purchases, Subject1&2=issued/sales & received/purchases (default: Subject2)')
    parser.add_argument('--output', choices=['table', 'json', 'csv'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--download-xml', action='store_true',
                        help='Download full XML for each invoice')
    parser.add_argument('--xml-output-dir', default='.',
                        help='Directory to save XML files (default: current directory)')
    parser.add_argument('--download-pdf', action='store_true',
                        help='Generate PDF for each invoice')
    parser.add_argument('--pdf-output-dir', default='.',
                        help='Directory to save PDF files (default: current directory)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    email_group = parser.add_argument_group('E-Mail sending')
    email_group.add_argument('--send-email', action='store_true',
                             help='Send invoices by E-Mail')
    email_group.add_argument('--smtp-host', help='SMTP server address')
    email_group.add_argument('--smtp-port', type=int, default=587,
                             help='SMTP server port (default: 587)')
    email_group.add_argument('--smtp-user', help='SMTP username')
    email_group.add_argument('--smtp-password', help='SMTP password')
    email_group.add_argument('--smtp-password-file', help='File containing SMTP password')
    email_group.add_argument('--email-from', help='Sender E-Mail address')
    email_group.add_argument('--email-to', action='append', metavar='ADDRESS',
                             help='Recipient E-Mail address (can be specified multiple times)')
    email_group.add_argument('--email-subject',
                             default='KSeF Invoice: {invoice_number}',
                             help='E-Mail subject template (default: "KSeF Invoice: {invoice_number}")')
    email_group.add_argument('--email-group', choices=['single', 'all'], default='single',
                             help='Grouping: single (one E-Mail per invoice, default) or all (all in one E-Mail)')

    args = parser.parse_args()

    if args.smtp_host and not args.send_email:
        args.send_email = True

    if not args.email_from and args.smtp_user:
        args.email_from = args.smtp_user

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    if args.xml_to_pdf:
        xml_path = args.xml_to_pdf
        _pdf_output_dir = args._pdf_output_dir

        ksefMisc.print_app_title(str_app_name, str_author)

        if not os.path.exists(xml_path):
            print(f"ERR: Path not found: {xml_path}", file=sys.stderr)
            sys.exit(1)

        if os.path.isfile(xml_path):
            xml_files = [xml_path]
        else:
            xml_files = sorted(
                f.path for f in os.scandir(xml_path)
                if f.is_file() and f.name.lower().endswith('.xml')
            )
            if not xml_files:
                print(f"ERR: No KSeF XML file(s) found in: {xml_path}", file=sys.stderr)
                sys.exit(1)

        os.makedirs(_pdf_output_dir, exist_ok=True)
        pdf_generator = ksefPDFGenerator.ksefPDFGenerator(logger=logger)

        print(f"Converting {len(xml_files)} KSeF XML file(s) to PDF in: {_pdf_output_dir}\n")
        err_count = 0
        for xml_file in xml_files:
            try:
                with open(xml_file, 'r', encoding='utf-8') as f:
                    xml_content = f.read()

                base_name = os.path.splitext(os.path.basename(xml_file))[0]
                pdf_path = os.path.join(_pdf_output_dir, f"{base_name}.pdf")
                pdf_generator.generate_pdf(xml_content, pdf_path)
                print(f"  OK: {xml_file} -> {pdf_path}")
                ok_count += 1
            except Exception as e:
                print(f"  ERR: {xml_file}: {e}", file=sys.stderr)
                err_count += 1

        print(f"\nDone. Converted KSeF XML files to PDF: {ok_count}, errors: {err_count}")
        sys.exit(0 if err_count == 0 else 1)

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

        if (subject_type == "Subject1&2"):
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

        if args.output == 'json':
            ksefMisc.print_invoices_json(invoicesData)
        elif args.output == 'csv':
            ksefMisc.print_invoices_csv(invoicesData)
        else:
            ksefMisc.print_invoices_table(invoicesData)

        xml_cache = {}
        pdf_cache = {}

        def get_xml_cached(ksef_number):
            if ksef_number not in xml_cache:
                xml_cache[ksef_number] = client.get_invoice_xml(ksef_number)
            return xml_cache[ksef_number]

        for invoicesSub in invoicesData:
            invoices = invoicesData[invoicesSub]

            if args.download_xml and invoices:
                _xml_output_dir = args.xml_output_dir
                _xml_output_dir = str(_xml_output_dir).replace('/', '\\')
                print(f"\nDownloading KSeF XML file(s) from {ksefMisc.ksefSubjectTypeLabels[invoicesSub]} to: {_xml_output_dir}")
                os.makedirs(_xml_output_dir, exist_ok=True)

                for inv in invoices:
                    ksef_number = inv.get('ksefNumber')
                    if ksef_number:
                        try:
                            xml_content = get_xml_cached(ksef_number)

                            safe_name = ksef_number.replace('/', '_').replace('\\', '_')
                            filepath = os.path.join(_xml_output_dir, f"{safe_name}.xml")
                            filepath = filepath.replace('/', '\\')
                            with open(filepath, 'w+', newline="\n", encoding='utf-8') as f:
                                f.write(xml_content)
                            print(f"  Downloaded: {filepath}")
                        except ksefError.ksefError as e:
                            print(f"  Error downloading {ksef_number}: {e.message}", file=sys.stderr)

            if args.download_pdf and invoices:
                _pdf_output_dir = args.pdf_output_dir
                _pdf_output_dir = str(_pdf_output_dir).replace('/', '\\')
                print(f"\nGenerating PDF file(s) to: {_pdf_output_dir}")
                os.makedirs(_pdf_output_dir, exist_ok=True)
                pdf_generator = ksefPDFGenerator.ksefPDFGenerator(logger=logger)

                for inv in invoices:
                    ksef_number = inv.get('ksefNumber')
                    if ksef_number:
                        try:
                            xml_content = get_xml_cached(ksef_number)

                            safe_name = ksef_number.replace('/', '_').replace('\\', '_')
                            filepath = os.path.join(_pdf_output_dir, f"{safe_name}.pdf")
                            filepath = filepath.replace('/', '\\')
                            pdf_generator.generate_pdf(xml_content, filepath)
                            pdf_cache[ksef_number] = filepath
                            print(f"  Generated: {filepath}")
                        except ksefError.ksefError as e:
                            print(f"  Error generating PDF for {ksef_number}: {e.message}", file=sys.stderr)
                        except Exception as e:
                            print(f"  Error generating PDF for {ksef_number}: {e}", file=sys.stderr)

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
