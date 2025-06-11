from datetime import datetime
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from pypdf import PdfReader, PdfWriter


def create_dynamic_stamp(output_path: Path, text: str):
    """Создаёт PDF-файл со штампом (одна страница)"""
    c = canvas.Canvas(str(output_path), pagesize=A4)
    c.setFont("Helvetica-Bold", 14)
    c.setFillColorRGB(1, 0, 0)
    c.drawString(400, 20, text)  # Позиция штампа (x=400, y=20)
    c.save()


def stamp_pdf_with_dynamic_text(input_pdf: Path, output_pdf: Path):
    timestamp = datetime.now().strftime("Signed : %Y-%m-%d %H:%M:%S")
    stamp_path = Path("stamp_temp.pdf")

    # Создаем штамп
    create_dynamic_stamp(stamp_path, timestamp)

    # Загружаем документы
    reader = PdfReader(input_pdf)
    stamp_reader = PdfReader(stamp_path)
    stamp_page = stamp_reader.pages[0]

    writer = PdfWriter()

    for page in reader.pages:
        page.merge_page(stamp_page)
        writer.add_page(page)

    with open(output_pdf, "wb") as out_f:
        writer.write(out_f)

    stamp_path.unlink()  # Удаляем временный файл

