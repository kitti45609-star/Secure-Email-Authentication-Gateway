
import dns.resolver

def check_dmarc(domain):

    print("\nDMARC Authentication Checker")
    print("----------------------------")

    try:
        records = dns.resolver.resolve(
            "_dmarc." + domain,
            "TXT"
        )

        for record in records:

            txt = record.to_text().strip('"')

            if "v=DMARC1" in txt:

                print("DMARC Record Found!")
                print("DNS Record:", txt)

                policy = "Not specified"

                for item in txt.split(";"):

                    item = item.strip()

                    if item.startswith("p="):
                        policy = item.split("=")[1]

                print("DMARC Policy:", policy.upper())

                if policy == "none":
                    print("Monitoring Mode Enabled")

                elif policy == "quarantine":
                    print("Suspicious emails should be quarantined")

                elif policy == "reject":
                    print("Unauthorized emails should be rejected")

                return

        print("No valid DMARC record found.")

    except dns.resolver.NXDOMAIN:
        print("DMARC record does not exist.")

    except dns.resolver.NoAnswer:
        print("No DMARC TXT record found.")

    except Exception as error:
        print("Error:", error)


domain = input("Enter domain name: ").strip()

if domain:
    check_dmarc(domain)
else:
    print("Please enter a valid domain name.")
