import yaml
import sys
import os
import re

def generate_curl_and_matchers(template_path, target_url):
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict) or "http" not in data:
                return "Template inválido ou não contém bloco 'http'."

            info = data.get("info", {})
            name = info.get("name", "N/A")
            cve = info.get("classification", {}).get("cve-id", "N/A")

            output = []

            for req in data["http"]:
                matchers_info = []

                matchers = req.get("matchers", [])
                if matchers:
                    for m in matchers:
                        tipo = m.get("type", "")
                        if tipo == "status":
                            statuses = m.get("status", [])
                            matchers_info.append(f"- Status: {', '.join(map(str, statuses))}")
                        elif tipo == "word":
                            words = m.get("words", [])
                            part = m.get("part", "body")
                            matchers_info.append(f"- Palavra no {part}: {', '.join(words)}")
                        elif tipo == "regex":
                            regexes = m.get("regex", [])
                            part = m.get("part", "body")
                            matchers_info.append(f"- Regex no {part}: {', '.join(regexes)}")
                        else:
                            matchers_info.append(f"- Matcher do tipo {tipo} encontrado.")

                if "raw" in req:
                    for raw_request in req["raw"]:
                        raw_request = re.sub(r"\{\{\s*Hostname\s*\}\}", target_url.replace("http://", "").replace("https://", ""), raw_request)
                        raw_request = re.sub(r"\{\{\s*BaseURL\s*\}\}", target_url, raw_request)

                        lines = raw_request.strip().split("\n")
                        first_line = lines[0]
                        method, path, _ = first_line.split()
                        headers = []
                        data_lines = []
                        is_data = False

                        for line in lines[1:]:
                            if line.strip() == "":
                                is_data = True
                                continue
                            if is_data:
                                data_lines.append(line)
                            else:
                                headers.append(line)

                        url = path if path.startswith("http") else target_url.rstrip("/") + path

                        curl_parts = ["curl", "-i"]
                        if url.startswith("https://"):
                            curl_parts.insert(1, "-k")
                        curl_parts += ["-X", method, f"'{url}'"]
                        for h in headers:
                            curl_parts += ["-H", f"\"{h.strip()}\""]
                        if data_lines:
                            body = "\\n".join(data_lines).replace("'", "'\\''")
                            curl_parts += ["--data", f"$'{body}'"]
                        curl = " ".join(curl_parts)

                        output.append((name, cve, curl, matchers_info))

                elif "path" in req:
                    method = req.get("method", "GET").upper()
                    paths = req.get("path", [])
                    headers = req.get("headers", {})
                    body = req.get("body", "")

                    for path in paths:
                        url = path if path.startswith("http") else target_url.rstrip("/") + path

                        curl_parts = ["curl", "-i"]
                        if url.startswith("https://"):
                            curl_parts.insert(1, "-k")
                        curl_parts += ["-X", method, f"'{url}'"]
                        for k, v in headers.items():
                            curl_parts += ["-H", f"\"{k}: {v}\""]
                        if body:
                            escaped_body = body.replace("'", "'\\''").replace("\n", "\\n")
                            curl_parts += ["--data", f"$'{escaped_body}'"]
                        curl = " ".join(curl_parts)

                        output.append((name, cve, curl, matchers_info))

            return output

    except Exception as e:
        return f"Erro ao processar o template: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 generate_curl_from_yaml.py <caminho_para_template.yaml> <url_alvo>")
        sys.exit(1)

    caminho = os.path.expanduser(sys.argv[1])
    alvo = sys.argv[2].rstrip("/")

    resultado = generate_curl_and_matchers(caminho, alvo)

    if isinstance(resultado, str):
        print(resultado)
    else:
        for i, (name, cve, cmd, matchers) in enumerate(resultado, 1):
            print(f"\n[{i}] CVE: {cve} | Vulnerabilidade: {name}")
            print(f"\nComando curl:\n{cmd}")
            if matchers:
                print("\n[+] Matchers esperados:")
                for m in matchers:
                    print(m)
            else:
                print("\n[+] Nenhum matcher definido no template.")
