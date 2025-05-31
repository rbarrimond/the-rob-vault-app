'''
This script retrieves the subclass information  for all characters of a Destiny 2 player using the Bungie API.
'''

import json
import requests

# Load tokens and user info from file
with open("tokens.json", "r") as f:
    tokens = json.load(f)

access_token = tokens["access_token"]
membership_type = tokens["membership_type"]
membership_id = tokens["membership_id"]

HEADERS = {
    "Authorization": f"Bearer {access_token}",
    "X-API-Key": "YOUR_API_KEY"  # Replace with your Bungie API key
}

# Get all character IDs


def get_characters():
    url = f"https://www.bungie.net/Platform/Destiny2/{membership_type}/Profile/{membership_id}/?components=200"
    res = requests.get(url, headers=HEADERS)
    res.raise_for_status()
    data = res.json()
    characters = data["Response"]["characters"]["data"]
    return list(characters.keys())

# Get subclass info for a character


def get_subclass(character_id):
    url = f"https://www.bungie.net/Platform/Destiny2/{membership_type}/Profile/{membership_id}/Character/{character_id}/?components=200,300"
    res = requests.get(url, headers=HEADERS)
    res.raise_for_status()
    data = res.json()
    equipped_items = data["Response"]["equipment"]["data"]["items"]
    subclass = next(
        (item for item in equipped_items if item["bucketHash"] == 3284755031), None)
    return subclass


# Run
if __name__ == "__main__":
    character_ids = get_characters()
    for char_id in character_ids:
        subclass = get_subclass(char_id)
        print(f"Character {char_id} Subclass: {subclass}")
