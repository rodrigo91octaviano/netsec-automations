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
    """Carrega todos os YAML dentro de rules/ (incluindo subpastas).
    Se algum YAML estiver quebrado, ignora e avisa no console.
    """
    rules = []

    for root, _, files in os.walk(RULES_DIR):
        for file in files:
            if file.endswith(".yaml"):
                path = os.path.join(root, file)

                try:
                    with open(path, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)

                    # YAML vazio ou inválido pode virar None
                    if not isinstance(rule, dict):
                        raise ValueError("YAML vazio ou inválido (não retornou um dict).")

                    rule["_file_path"] = path
                    rule["_file_name"] = file
                    rules.append(rule)

                except Exception as e:
                    print(f"[ERRO YAML] Falha ao carregar: {path}")
                    print(f"Motivo: {e}")
                    print("Regra ignorada.\n")

    return rules


def load_config_lines(path):
    """Carrega o running config (set format) em memória como lista de linhas."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f]


def find_latest_input_file(input_dir):
    """Pega o arquivo mais recente de inputs/<client>/ (maior mtime)."""
    files = [
        os.path.join(input_dir, f)
        for f in os.listdir(input_dir)
        if os.path.isfile(os.path.join(input_dir, f))
    ]

    if not files:
        raise FileNotFoundError(f"Nenhum arquivo encontrado em: {input_dir}")

    return max(files, key=os.path.getmtime)


def match_all_terms_same_line(terms, line):
    """Retorna True se TODOS os termos estiverem presentes na mesma linha."""
    return all(term in line for term in terms)


def evaluate_rule(rule, config_lines):
    """Executa uma regra e retorna um dict com resultado.
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
            "title": rule.get("output", {}).get("finding_title", rule_name),
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
                "title": rule.get("output", {}).get("finding_title", rule_name),
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


def save_csv(output_csv_path, results):
    """Gera a tabela CSV para abrir no Excel (somente FAIL e ERROR)."""
    with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["vulnerabilidade_encontrada", "comando_encontrado", "recomendacao", "fonte"]
        )
        writer.writeheader()

        for r in results:
            # Exporta FAIL e ERROR (pra você enxergar regra quebrada também)
            if r["status"] not in ("FAIL", "ERROR"):
                continue

            cmd = " | ".join(r["matched_lines"]) if r["matched_lines"] else ""

            writer.writerow({
                "vulnerabilidade_encontrada": r["title"] if r["status"] == "FAIL" else f"[ERRO REGRA] {r['title']}",
                "comando_encontrado": cmd,
                "recomendacao": r["recommendation"] if r["status"] == "FAIL" else (r.get("error") or "Erro ao executar regra."),
                "fonte": r["reference"]
            })


def wrap_text(text, max_chars=110):
    """Quebra texto para caber no PDF sem dependência extra."""
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


def save_pdf(output_pdf_path, client, input_file, scan_dt, results):
    """Gera PDF legível (somente FAIL e ERROR)."""
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

    total = len(results)
    failed = sum(1 for r in results if r["status"] == "FAIL")
    passed = sum(1 for r in results if r["status"] == "PASS")
    errors = sum(1 for r in results if r["status"] == "ERROR")

    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x, y, "Summary")
    y -= 0.6 * cm

    c.setFont("Helvetica", 10)
    c.drawString(margin_x, y, f"Total checks: {total} | PASS: {passed} | FAIL: {failed} | ERROR: {errors}")
    y -= 1.0 * cm

    # Achados (FAIL + ERROR)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin_x, y, "Findings (FAIL/ERROR)")
    y -= 0.7 * cm

    c.setFont("Helvetica", 10)

    findings = [r for r in results if r["status"] in ("FAIL", "ERROR")]

    if not findings:
        c.drawString(margin_x, y, "No findings. All checks passed.")
        c.save()
        return

    for idx, fnd in enumerate(findings, start=1):
        block_lines = []

        if fnd["status"] == "ERROR":
            block_lines.append(f"{idx}. [ERRO REGRA] {fnd['title']}  [{fnd['id']}]")
            block_lines.append("Detalhes do erro:")
            block_lines.extend(wrap_text(f"  {fnd.get('error','')}", max_chars=110))
            block_lines.append("Fonte:")
            block_lines.extend(wrap_text(f"  {fnd.get('reference','')}", max_chars=110))
        else:
            block_lines.append(f"{idx}. {fnd['title']}  [{fnd['id']}]  (Severity: {fnd['severity']})")
            block_lines.append("Command found:")
            if fnd["matched_lines"]:
                for ml in fnd["matched_lines"][:5]:
                    block_lines.extend(wrap_text(f"  - {ml}", max_chars=110))
                if len(fnd["matched_lines"]) > 5:
                    block_lines.append(f"  - ... ({len(fnd['matched_lines']) - 5} more)")
            else:
                block_lines.append("  - (none captured)")

            block_lines.append("Recommendation:")
            block_lines.extend(wrap_text(f"  {fnd['recommendation']}", max_chars=110))

            block_lines.append("Reference:")
            block_lines.extend(wrap_text(f"  {fnd['reference']}", max_chars=110))

        for line in block_lines:
            if y <= 2.2 * cm:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 2.0 * cm
            c.drawString(margin_x, y, line)
            y -= 0.45 * cm

        y -= 0.35 * cm

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
        try:
            results.append(evaluate_rule(rule, config_lines))
        except Exception as e:
            # Não para o scanner: registra erro e segue
            results.append({
                "id": rule.get("id", "UNKNOWN"),
                "title": rule.get("name", rule.get("title", "Regra com erro")),
                "category": rule.get("category", "UNKNOWN"),
                "severity": "ERROR",
                "status": "ERROR",
                "matched_lines": [],
                "recommendation": "Verificar erro na regra YAML.",
                "reference": rule.get("_file_name", "unknown"),
                "error": str(e)
            })

            print(f"[ERRO NA REGRA] {rule.get('_file_name')}")
            print(f"Motivo: {e}\n")

    save_csv(output_csv_path, results)
    save_pdf(output_pdf_path, client, input_file, scan_dt, results)

    print("Scan finalizado.")
    print(f"Input (latest): {input_file}")
    print(f"CSV: {output_csv_path}")
    print(f"PDF: {output_pdf_path}")


if __name__ == "__main__":
    run_scan("client-A")