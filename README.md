# 🔍 generate_curl_from_yaml_nuclei.py

Script Python para **extrair comandos `curl` e critérios de validação** a partir de templates do [Nuclei](https://nuclei.projectdiscovery.io/), facilitando testes manuais ou restritos em ambientes onde ferramentas automatizadas não são permitidas (ex: CTFs, ambientes monitorados, simulações de Red Team).

---

## 🚀 Funcionalidades

- ✅ Gera comandos `curl` baseados em templates `.yaml` do Nuclei
- ✅ Exibe nome da vulnerabilidade e CVE
- ✅ Mostra os critérios de validação (matchers: status, regex, palavras)
- ✅ Suporte a templates `raw` e `http`
- ✅ Adiciona `-k` automaticamente em URLs `https`
- ✅ Exibe os headers da resposta com `curl -i`

---

## 🧾 Exemplo de uso

```bash
python3 generate_curl_from_yaml_nuclei.py /caminho/para/template.yaml https://alvo.com
```
