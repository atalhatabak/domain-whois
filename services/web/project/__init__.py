#!/usr/bin/env python3
from html import escape

import dns.resolver
import whois
from flask import Flask, redirect, render_template, request
from time import sleep

app = Flask(__name__, static_folder="assets")

APP_TITLE = "Domain WHOIS Lookup"
DEFAULT_DOMAIN = "example.com"


@app.route("/<domain>", methods=["GET"])
def home_domain(domain):
    whois_body = process_domain(domain)
    dns_body = process_dns(domain)
    return display_homepage(domain, whois_body, dns_body)


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return redirect("/" + DEFAULT_DOMAIN)
    else:
        sleep(0.25)
        submitted_domain = str(request.form["domain"])
        submitted_domain = submitted_domain or DEFAULT_DOMAIN
        return redirect(f"/{submitted_domain}")


def process_domain(domain):
    page_body = ""

    try:
        domain_info = str(whois.whois(domain))
        domain_info = domain_info.replace("\n", "<BR>")

        page_body += domain_info

    except Exception:
        page_body += "Unable to perform domain WHOIS lookup, please try again."

    return page_body


def resolve_record(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(answer).strip() for answer in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
    ):
        return []


def process_dns(domain):
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "CAA", "SOA"]
    sections = []

    for record_type in record_types:
        records = resolve_record(domain, record_type)
        if not records:
            continue

        items = "".join(
            f"<li class='break-all'>{escape(record)}</li>" for record in records
        )
        sections.append(
            (
                "<div class='rounded-xl border border-base-300 bg-base-100 p-4'>"
                f"<h3 class='mb-2 text-sm font-semibold tracking-wide text-base-content/70'>{record_type} Records</h3>"
                f"<ul class='space-y-2'>{items}</ul>"
                "</div>"
            )
        )

    if not sections:
        return "Unable to find DNS records for this domain."

    return (
        "<div class='grid gap-4'>"
        + "".join(sections)
        + "</div>"
    )


def display_homepage(domain, whois_body, dns_body):
    return render_template(
        "home.html",
        app_title=APP_TITLE,
        domain=domain,
        whois_body=whois_body,
        dns_body=dns_body,
    )


if __name__ == "__main__":
    app.run()
