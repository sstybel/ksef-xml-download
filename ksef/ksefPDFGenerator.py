import os
import logging

from lxml import etree

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

from ksef import ksefFonts

_FONT_REGISTERED = False
_FONT_NAME = 'Helvetica'

def _register_polish_font(logger: logging.Logger = None):
    global _FONT_REGISTERED, _FONT_NAME
    if _FONT_REGISTERED:
        return

    fonts= ksefFonts.create_fonts()

    for font in fonts:
        font_path = fonts[font]
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont(font, font_path))
                _FONT_NAME = font
                logger.info(f"Registered font: {font_path}")
                break
            except Exception as e:
                logger.warning(f"Failed to register font {font_path}: {e}")
    
    ksefFonts.destroy_fonts(fonts)

    _FONT_REGISTERED = True

class ksefPDFGenerator:
    NAMESPACES = {
        'fa': 'http://crd.gov.pl/wzor/2025/06/25/13775/',
        'etd': 'http//crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/',
    }

    def __init__(
            self, 
            logger: logging.Logger = None
        ):

        self.logger = logger or logging.getLogger(__name__)

        _register_polish_font(self.logger)
        
        self.font_name = _FONT_NAME
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        for style_name in ['Normal', 'Heading1', 'Heading2', 'Heading3', 'BodyText']:
            if style_name in self.styles:
                self.styles[style_name].fontName = self.font_name

        self.styles.add(ParagraphStyle(
            name='InvoiceTitle',
            fontName=self.font_name,
            fontSize=16,
            leading=20,
            alignment=1,
            spaceAfter=10,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            fontName=self.font_name,
            fontSize=11,
            leading=14,
            spaceBefore=10,
            spaceAfter=5,
            textColor=colors.HexColor('#333333'),
        ))
        self.styles.add(ParagraphStyle(
            name='CompanyName',
            fontName=self.font_name,
            fontSize=10,
            leading=12,
        ))
        self.styles.add(ParagraphStyle(
            name='CompanyDetails',
            fontName=self.font_name,
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#555555'),
        ))
        self.styles.add(ParagraphStyle(
            name='Footer',
            fontName=self.font_name,
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#666666'),
        ))

    def _get_text(self, element, xpath: str, default: str = '') -> str:
        for prefix, ns in self.NAMESPACES.items():
            try:
                result = element.find(xpath.replace('//', f'//{prefix}:').replace('/', f'/{prefix}:'), {prefix: ns})
                if result is not None and result.text:
                    return result.text.strip()
            except Exception:
                pass

        try:
            for elem in element.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}')[1]
            result = element.find(xpath.lstrip('/'))
            if result is not None and result.text:
                return result.text.strip()
        except Exception:
            pass

        return default

    def _parse_xml(self, xml_content: str) -> dict:
        xml_clean = xml_content
        root = etree.fromstring(xml_clean.encode('utf-8'))

        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}')[1]

        data = {
            'invoice_number': '',
            'invoice_date': '',
            'currency': 'PLN',
            'seller': {},
            'buyer': {},
            'items': [],
            'summary': {},
            'payment': {},
            'additional_descriptions': [],
            'pricing_type': 'net',
            'footer': [],
        }

        fa = root.find('.//Fa')
        if fa is not None:
            data['invoice_number'] = fa.findtext('P_2', '')
            data['invoice_date'] = fa.findtext('P_1', '')
            data['currency'] = fa.findtext('KodWaluty', 'PLN')

            okres = fa.find('OkresFa')
            if okres is not None:
                data['period_from'] = okres.findtext('P_6_Od', '')
                data['period_to'] = okres.findtext('P_6_Do', '')

            vat_rate_fields = [
                ('P_13_1', 'P_14_1', 'P_14_1W', '23%'),
                ('P_13_2', 'P_14_2', 'P_14_2W', '22%'),
                ('P_13_3', 'P_14_3', 'P_14_3W', '8%'),
                ('P_13_4', 'P_14_4', 'P_14_4W', '7%'),
                ('P_13_5', 'P_14_5', 'P_14_5W', '5%'),
                ('P_13_6_1', None, None, '0%'),
                ('P_13_6_2', None, None, '0% (WDT)'),
                ('P_13_6_3', None, None, '0% (eksport)'),
                ('P_13_7', None, None, 'zw'),
                ('P_13_8', None, None, 'np'),
            ]
            rates = []
            for net_field, vat_field, vat_conv_field, label in vat_rate_fields:
                net = self._parse_amount(fa.findtext(net_field, ''))
                vat = self._parse_amount(fa.findtext(vat_field, '')) if vat_field else 0.0
                vat_conv = self._parse_amount(fa.findtext(vat_conv_field, '')) if vat_conv_field else 0.0
                if net:
                    rates.append({'label': label, 'net': net, 'vat': vat, 'vat_converted': vat_conv})
            data['summary'] = {
                'rates': rates,
                'gross': self._parse_amount(fa.findtext('P_15', '0')),
            }

            for wiersz in fa.findall('FaWiersz'):
                item = {
                    'lp': wiersz.findtext('NrWierszaFa', ''),
                    'name': wiersz.findtext('P_7', ''),
                    'unit': wiersz.findtext('P_8A', ''),
                    'qty': self._parse_amount(wiersz.findtext('P_8B', '1')),
                    'unit_price_net': self._parse_amount(wiersz.findtext('P_9A', '')),
                    'unit_price_gross': self._parse_amount(wiersz.findtext('P_9B', '')),
                    'net_value': self._parse_amount(wiersz.findtext('P_11', '')),
                    'gross_value': self._parse_amount(wiersz.findtext('P_11A', '')),
                    'vat_rate': wiersz.findtext('P_12', ''),
                    'vat_value': self._parse_amount(wiersz.findtext('P_11Vat', '')),
                }
                data['items'].append(item)

            has_net_prices = any(item['unit_price_net'] for item in data['items'])
            data['pricing_type'] = 'net' if has_net_prices else 'gross'

            for opis in fa.findall('DodatkowyOpis'):
                klucz = opis.findtext('Klucz', '')
                wartosc = opis.findtext('Wartosc', '')
                if klucz or wartosc:
                    data['additional_descriptions'].append({'key': klucz, 'value': wartosc})

            platnosc = fa.find('Platnosc')
            if platnosc is not None:
                data['payment']['description'] = platnosc.findtext('OpisPlatnosci', '')
                data['payment']['form'] = platnosc.findtext('FormaPlatnosci', '')
                terminy = platnosc.findall('TerminPlatnosci')
                due_dates = []
                for termin in terminy:
                    date = termin.findtext('Termin', '') or (termin.text.strip() if termin.text else '')
                    if date:
                        due_dates.append(date)
                data['payment']['due_dates'] = due_dates
                rachunek = platnosc.find('RachunekBankowy')
                if rachunek is not None:
                    data['payment']['bank_account'] = rachunek.findtext('NrRB', '')
                    data['payment']['bank_name'] = rachunek.findtext('NazwaBanku', '')

        podmiot1 = root.find('.//Podmiot1')
        if podmiot1 is not None:
            dane = podmiot1.find('DaneIdentyfikacyjne')
            adres = podmiot1.find('Adres')
            data['seller'] = {
                'nip': dane.findtext('NIP', '') if dane is not None else '',
                'name': dane.findtext('Nazwa', '') if dane is not None else '',
                'address1': adres.findtext('AdresL1', '') if adres is not None else '',
                'address2': adres.findtext('AdresL2', '') if adres is not None else '',
                'country': adres.findtext('KodKraju', 'PL') if adres is not None else 'PL',
            }

        podmiot2 = root.find('.//Podmiot2')
        if podmiot2 is not None:
            dane = podmiot2.find('DaneIdentyfikacyjne')
            adres = podmiot2.find('Adres')
            data['buyer'] = {
                'nip': dane.findtext('NIP', '') if dane is not None else '',
                'name': dane.findtext('Nazwa', '') if dane is not None else '',
                'address1': adres.findtext('AdresL1', '') if adres is not None else '',
                'address2': adres.findtext('AdresL2', '') if adres is not None else '',
                'country': adres.findtext('KodKraju', 'PL') if adres is not None else 'PL',
            }

        stopka = root.find('.//Stopka')
        if stopka is not None:
            for info in stopka.findall('.//StopkaFaktury'):
                if info.text:
                    data['footer'].append(info.text.strip())
            rejestry = stopka.find('Rejestry')
            if rejestry is not None:
                krs = rejestry.findtext('KRS', '')
                regon = rejestry.findtext('REGON', '')
                if krs:
                    data['footer'].append(f'KRS: {krs}')
                if regon:
                    data['footer'].append(f'REGON: {regon}')

        return data

    def _parse_amount(self, value: str) -> float:
        if not value:
            return 0.0
        try:
            return float(value.replace(',', '.').replace(' ', ''))
        except ValueError:
            return 0.0

    def _format_amount(self, amount: float, currency: str = 'PLN') -> str:
        return f"{amount:,.2f} {currency}".replace(',', ' ').replace('.', ',').replace(' ', ' ')

    def generate_pdf(self, xml_content: str, output_path: str) -> str:
        """
        Generate PDF from KSeF XML invoice.

        Args:
            xml_content: Invoice XML content
            output_path: Path to save PDF file

        Returns:
            Path to generated PDF
        """
        data = self._parse_xml(xml_content)
        currency = data.get('currency', 'PLN')

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=15*mm,
            leftMargin=15*mm,
            topMargin=15*mm,
            bottomMargin=15*mm
        )

        elements = []

        title = Paragraph(f"FAKTURA VAT nr {data['invoice_number']}", self.styles['InvoiceTitle'])
        elements.append(title)

        date_text = f"Data wystawienia: {data['invoice_date']}"
        if data.get('period_from') and data.get('period_to'):
            date_text += f"<br/>Okres rozliczeniowy: {data['period_from']} - {data['period_to']}"
        elements.append(Paragraph(date_text, self.styles['Normal']))
        elements.append(Spacer(1, 10*mm))

        seller = data.get('seller', {})
        buyer = data.get('buyer', {})

        parties_data = [
            [
                Paragraph("<b>SPRZEDAWCA</b>", self.styles['SectionHeader']),
                Paragraph("<b>NABYWCA</b>", self.styles['SectionHeader'])
            ],
            [
                Paragraph(f"<b>{seller.get('name', '')}</b>", self.styles['CompanyName']),
                Paragraph(f"<b>{buyer.get('name', '')}</b>", self.styles['CompanyName'])
            ],
            [
                Paragraph(f"NIP: {seller.get('nip', '')}", self.styles['CompanyDetails']),
                Paragraph(f"NIP: {buyer.get('nip', '')}", self.styles['CompanyDetails'])
            ],
            [
                Paragraph(seller.get('address1', ''), self.styles['CompanyDetails']),
                Paragraph(buyer.get('address1', ''), self.styles['CompanyDetails'])
            ],
            [
                Paragraph(seller.get('address2', ''), self.styles['CompanyDetails']),
                Paragraph(buyer.get('address2', ''), self.styles['CompanyDetails'])
            ],
        ]

        parties_table = Table(parties_data, colWidths=[90*mm, 90*mm])
        parties_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(parties_table)
        elements.append(Spacer(1, 8*mm))

        elements.append(Paragraph("<b>POZYCJE FAKTURY</b>", self.styles['SectionHeader']))

        pricing_type = data.get('pricing_type', 'net')
        if pricing_type == 'net':
            price_label = 'Cena netto'
            value_label = 'Wartość netto'
        else:
            price_label = 'Cena brutto'
            value_label = 'Wartość brutto'

        items_header = ['Lp.', 'Nazwa towaru/usługi', 'J.m.', 'Ilość', price_label, value_label, 'VAT']
        items_data = [items_header]

        for item in data.get('items', []):
            if pricing_type == 'net':
                unit_price = item.get('unit_price_net') or item.get('unit_price_gross', 0)
                value = item.get('net_value') or item.get('gross_value', 0)
            else:
                unit_price = item.get('unit_price_gross') or item.get('unit_price_net', 0)
                value = item.get('gross_value') or item.get('net_value', 0)

            vat_rate = item.get('vat_rate', '')
            if vat_rate and vat_rate not in ('zw', 'np', 'oo'):
                vat_display = f"{vat_rate}%"
            else:
                vat_display = vat_rate

            row = [
                item['lp'],
                Paragraph(item['name'], self.styles['Normal']),
                item['unit'],
                f"{item['qty']:.2f}".replace('.', ','),
                self._format_amount(unit_price, ''),
                self._format_amount(value, ''),
                vat_display,
            ]
            items_data.append(row)

        col_widths = [10*mm, 70*mm, 15*mm, 15*mm, 25*mm, 25*mm, 15*mm]
        items_table = Table(items_data, colWidths=col_widths)
        items_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
            ('ALIGN', (3, 1), (-1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F2F2')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(items_table)
        elements.append(Spacer(1, 8*mm))

        elements.append(Paragraph("<b>PODSUMOWANIE</b>", self.styles['SectionHeader']))

        summary = data.get('summary', {})
        summary_data = []

        for rate in summary.get('rates', []):
            summary_data.append([
                f"Wartość netto ({rate['label']}):",
                self._format_amount(rate['net'], currency)
            ])
            if rate.get('vat'):
                summary_data.append([
                    f"VAT ({rate['label']}):",
                    self._format_amount(rate['vat'], currency)
                ])
            if rate.get('vat_converted'):
                summary_data.append([
                    f"VAT ({rate['label']}) w PLN:",
                    self._format_amount(rate['vat_converted'], 'PLN')
                ])

        summary_data.append(['', ''])
        summary_data.append([
            '<b>RAZEM DO ZAPŁATY:</b>',
            f"<b>{self._format_amount(summary.get('gross', 0), currency)}</b>"
        ])

        summary_table_data = [[Paragraph(str(row[0]), self.styles['Normal']),
                               Paragraph(str(row[1]), self.styles['Normal'])] for row in summary_data]

        summary_table = Table(summary_table_data, colWidths=[120*mm, 55*mm])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(summary_table)

        payment = data.get('payment', {})
        if any(payment.values()):
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("<b>PŁATNOŚĆ</b>", self.styles['SectionHeader']))

            payment_form_names = {
                '1': 'gotówka', '2': 'karta', '3': 'bon', '4': 'czek',
                '5': 'kredyt', '6': 'przelew', '7': 'mobilna',
            }
            if payment.get('form'):
                form_display = payment_form_names.get(payment['form'], payment['form'])
                elements.append(Paragraph(f"Forma płatności: {form_display}", self.styles['Normal']))
            if payment.get('due_dates'):
                for date in payment['due_dates']:
                    elements.append(Paragraph(f"Termin płatności: {date}", self.styles['Normal']))
            if payment.get('bank_account'):
                line = f"Nr rachunku: {payment['bank_account']}"
                if payment.get('bank_name'):
                    line += f" ({payment['bank_name']})"
                elements.append(Paragraph(line, self.styles['Normal']))
            if payment.get('description'):
                elements.append(Paragraph(f"{payment['description']}", self.styles['Normal']))

        additional_descs = data.get('additional_descriptions', [])
        if additional_descs:
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("<b>INFORMACJE DODATKOWE</b>", self.styles['SectionHeader']))
            for desc in additional_descs:
                key = desc.get('key', '')
                value = desc.get('value', '')
                if key and value:
                    elements.append(Paragraph(f"<b>{key}:</b> {value}", self.styles['Normal']))
                elif value:
                    elements.append(Paragraph(value, self.styles['Normal']))

        if data.get('footer'):
            elements.append(Spacer(1, 10*mm))
            elements.append(Paragraph("<b>Informacje dodatkowe:</b>", self.styles['Footer']))
            for line in data['footer']:
                elements.append(Paragraph(line, self.styles['Footer']))

        elements.append(Spacer(1, 5*mm))
        elements.append(Paragraph(
            "Faktura wygenerowana z Krajowego Systemu e-Faktur (KSeF)",
            self.styles['Footer']
        ))

        doc.build(elements)
        return output_path
