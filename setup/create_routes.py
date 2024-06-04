STRAT1_DOMAINS = ("alexbers.com", )
STRAT2_DOMAINS = ("oaiusercontent.com", "oaistatic.com", "openai.com", "chatgpt.com", "coursera.org")

with open("routes.txt", "w") as f:
    for domain in sorted(STRAT1_DOMAINS):
        print(domain, 1, file=f)
    for domain in sorted(STRAT2_DOMAINS):
        print(domain, 2, file=f)

print("routes.txt created")
