
from flask import Flask, render_template, request
import spf
import dkim
import dns.resolver

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


def check_spf(sender_ip, sender_email):
    try:
        domain = sender_email.split("@")[-1]

        result, explanation = spf.check2(
            i=sender_ip,
            s=sender_email,
            h=domain
        )

        return result.upper()

    except Exception:
        return "ERROR"


def check_dkim(email_message):
    try:
        if "dkim-signature:" not in email_message.lower():
            return "NO SIGNATURE"

        # DKIM verification requires the complete raw email,
        # including its headers and body.
        if "\n\n" not in email_message and "\r\n\r\n" not in email_message:
            return "INCOMPLETE EMAIL"

        email_data = email_message.encode("utf-8")

        if dkim.verify(email_data):
            return "PASS"
        else:
            return "FAIL"

    except Exception:
        return "ERROR"


def check_dmarc(domain):
    try:
        records = dns.resolver.resolve(
            "_dmarc." + domain,
            "TXT"
        )

        for record in records:

            txt = b"".join(record.strings).decode("utf-8")

            if "v=DMARC1" in txt.upper():

                policy = "Not specified"

                for item in txt.split(";"):
                    item = item.strip()

                    if item.lower().startswith("p="):
                        policy = item.split("=", 1)[1].strip()

                return "RECORD FOUND (p=" + policy.upper() + ")"

        return "NO VALID DMARC RECORD"

    except dns.resolver.NXDOMAIN:
        return "NO DMARC RECORD"

    except dns.resolver.NoAnswer:
        return "NO DMARC RECORD"

    except Exception:
        return "ERROR"


@app.route("/check", methods=["POST"])
def check_email():

    email_message = request.form.get(
        "email_header", ""
    ).strip()

    sender_ip = request.form.get(
        "sender_ip", ""
    ).strip()

    sender_email = request.form.get(
        "sender_email", ""
    ).strip()

    if not email_message:
        return render_template(
            "index.html",
            error="Please enter the complete email message."
        )

    if "@" not in sender_email:
        return render_template(
            "index.html",
            error="Please enter a valid sender email address."
        )

    domain = sender_email.split("@")[-1]

    results = {
        "spf": "Not checked",
        "dkim": "Not checked",
        "dmarc": "Not checked"
    }

    # SPF Authentication
    if sender_ip:
        results["spf"] = check_spf(
            sender_ip,
            sender_email
        )

    # DKIM Authentication
    results["dkim"] = check_dkim(email_message)

    # DMARC DNS Record Lookup
    results["dmarc"] = check_dmarc(domain)

    return render_template(
        "index.html",
        results=results
    )


if __name__ == "__main__":
    app.run(debug=True)
