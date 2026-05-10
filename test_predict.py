from predict import predict_url

test_urls = [
    "https://www.google.com",
    "https://www.facebook.com/",
    "https://www.youtube.com",
    "https://paypal-login-secure.com",
    "http://192.168.0.1/login",
    "https://secure-update-account-verify.com",
    "https://github.com/",
    "https://translate.google.com/?sl=en&tl=ms&op=translate",
    "signin.eby.de.zukruygxctzmmqi.civpro.co.za",
    "https://www.wattpad.com",
    "https://www.instagram.com/?hl=en",
    "https://www.instagram.com",
    "https://www.paypal.com/my/home",
    "https://cdn.tngdigital.sit-e.com/app/?data=abcdefghijklmnopqrstuvwxyz1234567890&session=99887766554433221100alphaomega&tracking=marketing_digital_transformation_high_priority_campaign_node_001&auth=zxyvutswrqponmlkjihgfedcba_1234567890_security_verified_standard_encryption&source=offline_print_advertisement_billboard_flyer_brochure_v2&status=active_verified_system_access_high_density_module_matrix_version_40",
    "https://www.google.com/search?q=translate&rlz=1C1GCEA_enMY1141MY1141&oq=tr&gs_lcrp=EgZjaHJvbWUqEggAEAAYQxiDARixAxiABBiKBTISCAAQABhDGIMBGLEDGIAEGIoFMgwIARAAGEMYgAQYigUyEggCEC4YQxjHARjRAxiABBiKBTIPCAMQABhDGLEDGIAEGIoFMgwIBBAAGEMYgAQYigUyDwgFEAAYQxixAxiABBiKBTIGCAYQBRhAMgYIBxBFGDzSAQgxNDM5ajBqOagCBrACAfEFwOr3NyG_43o&sourceid=chrome&ie=UTF-8",
    
    # --- Homograph / Typosquatting attacks ---
    "https://www.paypa1.com",           # '1' instead of 'l'
    "https://www.g00gle.com",           # zeros instead of 'o'
    "https://www.arnazon.com",          # 'rn' looks like 'm'

    # --- Legitimate URLs that look suspicious ---
    "https://www.booking.com/hotel/my/login.html",   # has 'login' but legit
    "https://account.microsoft.com/profile",          # has 'account' but legit
    "https://security.microsoft.com",                 # has 'security' but legit

    # --- Malaysian context ---
    "https://www.maybank2u.com.my",
    "https://www.cimb.com.my",
    "https://mytax.hasil.gov.my",
    "https://www.padu.gov.my",

    # --- Phishing with HTTPS (common misconception HTTPS = safe) ---
    "https://paypal-secure-login.verify-account.com",
    "https://apple-id-verify.support-login.com",
    "https://evil.com@google.com",

    # --- Empty / weird inputs ---
    "https://",
    "notaurl",
    "javascript:alert(1)",          # XSS attempt in URL field
    
    "https://jawatan-kosong-terkini.semak-now.online/1/",   # Should be Malicious
    "http://www.olddubliner.de/Drinks/ODHH_DrinksMenu.pdf", # Should be Benign
    "https://bantuan-kerajaan.online",                       # Should be Malicious
    "https://semak-brim.xyz",                                # Should be Malicious
    
    "https://qrco.de/bgnRSm",
    "https://tinyurl.com/3dr54rzm",
    "https://qrco.de/bgnRTd"
    ]

print("\n===== URL PREDICTION TEST =====\n")

for url in test_urls:
    result = predict_url(url)
    print(f"{url} → {result}")

print("\n===== TEST COMPLETE =====")

