
import os
import openai

openai.api_key = os.getenv("OPENAI_API_KEY")

def review_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    prompt = f"Fais une revue de ce fichier Python et suggère des améliorations :\n\n{content}"

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    print(response["choices"][0]["message"]["content"])

if __name__ == "__main__":
    review_file("main.py")
