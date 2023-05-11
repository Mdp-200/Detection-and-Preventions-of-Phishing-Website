import re
import urllib.request
from bs4 import BeautifulSoup
import whois
import datetime
import time
import socket
import requests
import sys
from tldextract import extract
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import numpy as np
from sklearn import svm
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib

# Load the trained model
clf = joblib.load('phishing_detector.pkl')

# Function to extract domain information from URL
def get_domain_info(url):
    domain_parts = extract(url)
    return domain_parts

# Function to check if URL has an IP address instead of a domain name
def check_ip_address(url):
    parts = url.split('.')
    if len(parts) == 4:
        for part in parts:
            if not part.isdigit():
                return False
        return True
    return False

# Function to check if URL has '@' symbol
def check_at_symbol(url):
    if '@' in url:
        return True
    return False

# Function to extract URL features
def extract_features(url):
    features = []
    # Domain information features
    domain_parts = get_domain_info(url)
    features.append(len(domain_parts.subdomain))
    features.append(len(domain_parts.domain))
    features.append(len(domain_parts.suffix))
    # URL length feature
    features.append(len(url))
    # IP address feature
    features.append(check_ip_address(url))
    # '@' symbol feature
    features.append(check_at_symbol(url))
    # SSL certificate feature
    try:
        response = requests.get(url, verify=True, timeout=5)
        cert_status = 1 if response.status_code == 200 and response.url.startswith('https') else 0
        features.append(cert_status)
    except:
        features.append(0)
    # WHOIS and age of domain features
    try:
        domain_info = whois.whois(url)
        if domain_info.creation_date is not None and domain_info.expiration_date is not None:
            age_of_domain = (domain_info.expiration_date - domain_info.creation_date).days
            features.append(age_of_domain)
            features.append(1)
        else:
            features.append(-1)
            features.append(-1)
    except:
        features.append(-1)
        features.append(-1)
    return features

# Function to predict if URL is a phishing website or not
def predict_phishing_website(url):
    # Extract features from URL
    features = extract_features(url)
    # Make prediction using trained model
    prediction = clf.predict([features])
    return prediction

# Main function to take user input and predict if URL is a phishing website or not
def main():
    url = input("Enter url : ")
    prediction = predict_phishing_website(url)
    if prediction == -1:
        print("Not a phishing website")
    else:
        print("Phishing website detected")
        # Store URL in database
        try:
            conn = sqlite3.connect('phishing_urls.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO urls (url, is_phishing) VALUES (?, ?)", (url, 1))
            conn.commit()
            conn.close()
            print("Inserted into database")
        except:
            print("Error inserting into database")

if __name__ == '__main__':
    main()
