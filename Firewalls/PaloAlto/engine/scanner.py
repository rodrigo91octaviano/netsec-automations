import os
import csv
import yaml
from datetime import datetime

# PDF (instalar no Windows: python -m pip install reportlab)
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULES_DIR = os.path.join(BASE_DIR, "rules")
INPUTS_DIR = os.path.join(BASE_DIR, "inputs")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")


def load_rules():
    """Carrega todos os YAML dentro de rules/ (incluindo subpastas)."""
    rules = []

    for root, _, files in os.walk(RULES_DIR):
        for file in files:
            if file.endswith(".yaml"):
                path = os.path.join(root, file)

                with open(path, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)

                rule["_file_path"] = path
                rule["_file_name"] = file
                rules.append(rule)

    return rules


def load_config_lines(path):
    """Carrega o running config (set format) em memória como lista de linhas."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f]


def find_latest_input_file(input_dir):
    """
    Pega o arquivo mais recente de inputs/<client>/.
    Critério simples: maior mtime (data de modificação).
    """
    files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    if not files:
        raise FileNotFoundError(f"Nenhum arquivo encontrado em: {input_dir}")

    return max(files, key=os.path.getmtime)


def match_all_terms_same_line(terms, line):
    """Retorna True se TODOS os termos estiverem presentes na mesma linha."""
    return all(term in line for term in terms)


def evaluate_rule(rule, config_lines):
    """
    Executa uma regra e retorna um dict com resultado.
    Suporta:
      - forbidden_line: se achar match => FAIL
      - required_line: se NÃO achar match => FAIL
    Match:
      - all_terms_in_same_line + terms
    """
    rule_id = rule.get("id", "NO-ID")
    rule_name = rule.get("name", rule.get("title", rule_id))
    severity = rule.get("severity", "UNKNOWN")
    category = rule.get("category", "GENERAL")

    check = rule.get("check", {})
    check_type = check.get("type", "forbidden_line")
    match = check.get("match", {})
    mode = match.get("mode", "all_terms_in_same_line")
    terms = match.get("terms", [])

    if not terms:
        return {
            "id": rule_id,
            "title": rule_name,
            "category": category,
            "severity": severity,
            "status": "ERROR",
            "matched_lines": [],
            "recommendation": rule.get("output", {}).get("recommendation", ""),
            "reference": rule.get("output", {}).get("reference", ""),
            "error": "Regra sem 'terms' para match."
        }

    matched = []

    for line in config_lines:
        if mode == "all_terms_in_same_line":
            if match_all_terms_same_line(terms, line):
                matched.append(line.strip())

        else:
            return {
                "id": rule_id,
                "title": rule_name,
                "category": category,
                "severity": severity,
                "status": "ERROR",
                "matched_lines": [],
                "recommendation": rule.get("output", {}).get("recommendation", ""),
                "reference": rule.get("output", {}).get("reference", ""),
                "error": f"Modo de match não suportado: {mode}"
            }

    # Decide PASS/FAIL conforme o tipo
    if check_type == "forbidden_line":
        status = "FAIL" if matched else "PASS"
    elif check_type == "required_line":
        status = "PASS" if matched else "FAIL"
    else:
        status = "ERROR"

    return {
        "id": rule_id,
        "title": rule.get("output", {}).get("finding_title", rule_name),
        "category": category,
        "severity": severity,
        "status": status,
        "matched_lines": matched,
        "recommendation": rule.get("output", {}).get("recommendation", ""),
        "reference": rule.get("output", {}).get("reference", ""),
        "error": ""
    }


def save_csv(output_csv_path, findings):
    """Gera a tabela CSV para abrir no Excel."""
    with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["vulnerabilidade_encontrada", "comando_encontrado", "recomendacao", "fonte"]
        )
        writer.writeheader()

        for f in findings:
            # Se houver várias linhas batendo, a gente concatena com " | "
            cmd = " | ".join(f["matched_lines"]) if f["matched_lines"] else ""

            # Só exporta FAIL por padrão (mais útil). Se quiser tudo, mude aqui.
            if f["status"] == "FAIL":
                writer.writerow({
                    "vulnerabilidade_encontrada": f["title"],
                    "comando_encontrado": cmd,
                    "recomendacao": f["recommendation"],
                    "fonte": f["reference"]
                })


def wrap_text(text, max_chars=110):
    """Quebra texto para caber no PDF sem depender de biblioteca extra."""
    words = text.split()
    lines = []
    current = []

    for w in words:
        if len(" ".join(current + [w])) <= max_chars:
            current.append(w)
        else:
            lines.append(" ".join(current))
            current = [w]

    if current:
        lines.append(" ".join(current))

    return lines


def save_pdf(output_pdf_path, client, input_file, scan_dt, findings):
    """Gera PDF legível (estilo relatório) com os FAILs."""
    c = canvas.Canvas(output_pdf_path, pagesize=A4)
    width, height = A4

    margin_x = 2.0 * cm
    y = height - 2.0 * cm

    # Cabeçalho
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin_x, y, "Palo Alto Hardening Scanner - Report")
    y -= 0.8 * cm

    c.setFont("Helvetica", 10)
    c.drawString(margin_x, y, f"Client: {client}")
    y -= 0.5 * cm
    c.drawString(margin_x, y, f"Input: {os.path.basename(input_file)}")
    y -= 0.5 * cm
    c.drawString(margin_x, y, f"Scan date: {scan_dt}")
    y -= 1.0 * cm

    # Resumo
    total = len(findings)
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    passed = sum(1 for f in findings if f["status"] == "PASS")
    errors = sum(1 for f in findings if f["status"] == "ERROR")

    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x, y, "Summary")
    y -= 0.6 * cm

    c.setFont("Helvetica", 10)
    c.drawString(margin_x, y, f"Total checks: {total} | PASS: {passed} | FAIL: {failed} | ERROR: {errors}")
    y -= 1.0 * cm

    # Achados (somente FAIL)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x, y, "Findings (FAIL)")
    y -= 0.7 * cm

    c.setFont("Helvetica", 10)

    fail_findings = [f for f in findings if f["status"] == "FAIL"]

    if not fail_findings:
        c.drawString(margin_x, y, "No findings. All checks passed.")
        c.save()
        return

    for idx, fnd in enumerate(fail_findings, start=1):
        block_lines = []

        block_lines.append(f"{idx}. {fnd['title']}  [{fnd['id']}]  (Severity: {fnd['severity']})")
        if fnd["matched_lines"]:
            block_lines.append("Command found:")
            for ml in fnd["matched_lines"][:5]:  # limita para não explodir o PDF
                block_lines.extend(wrap_text(f"  - {ml}", max_chars=110))
            if len(fnd["matched_lines"]) > 5:
                block_lines.append(f"  - ... ({len(fnd['matched_lines']) - 5} more)")
        else:
            block_lines.append("Command found: (none captured)")

        block_lines.append("Recommendation:")
        block_lines.extend(wrap_text(f"  {fnd['recommendation']}", max_chars=110))

        block_lines.append("Reference:")
        block_lines.extend(wrap_text(f"  {fnd['reference']}", max_chars=110))

        # escreve bloco
        for line in block_lines:
            if y <= 2.2 * cm:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 2.0 * cm
            c.drawString(margin_x, y, line)
            y -= 0.45 * cm

        y -= 0.35 * cm  # espaço entre achados

    c.save()


def run_scan(client):
    input_dir = os.path.join(INPUTS_DIR, client)
    output_dir = os.path.join(OUTPUTS_DIR, client)
    os.makedirs(output_dir, exist_ok=True)

    input_file = find_latest_input_file(input_dir)
    config_lines = load_config_lines(input_file)

    rules = load_rules()

    scan_dt = datetime.now().strftime("%Y-%m-%d_%H%M")
    output_csv_path = os.path.join(output_dir, f"report_{scan_dt}.csv")
    output_pdf_path = os.path.join(output_dir, f"report_{scan_dt}.pdf")

    results = []
    for rule in rules:
        results.append(evaluate_rule(rule, config_lines))

    # CSV: só FAIL (tabela)
    save_csv(output_csv_path, results)

    # PDF: legível humano
    save_pdf(output_pdf_path, client, input_file, scan_dt, results)

    print("Scan finalizado.")
    print(f"Input (latest): {input_file}")
    print(f"CSV: {output_csv_path}")
    print(f"PDF: {output_pdf_path}")


if __name__ == "__main__":
    # Troque aqui para o cliente desejado
    run_scan("client-A")