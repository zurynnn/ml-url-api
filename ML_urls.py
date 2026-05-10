#Import libraries
import os
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report,  roc_curve, auc
from sklearn.model_selection import train_test_split
from sklearn.dummy import DummyClassifier #dummy
from sklearn.ensemble import RandomForestClassifier #algorithm
from xgboost import XGBClassifier #algorithm

#Visualizations
VISUALIZATION_DIR = r"D:\UniKL Assignment [new]\UniKL Sem5\FYP 1\Prototype\ML URL Training\ML Visualization"
os.makedirs(VISUALIZATION_DIR, exist_ok=True)

#Datasets load
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dataset= pd.read_csv(os.path.join(BASE_DIR, "processed_urls.csv"))  # merged url training

#Datasets checking
print(dataset.info()) #row,column,data types info
print("Dataset:", dataset.shape) #dataset size
print("Dataset label counts:", dataset['label'].value_counts()) #sh class distribution (imbalance)

#Feature/labels select
X = dataset.drop(columns=["url", "label", "result"]) #Features (what the model learns from)
y = dataset["result"] #result (what the model predicts)

#Sanity check
print("Unique labels:", y.unique())

# Dataset split: 70% train, 15% validation, 15% test
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)

X_valid, X_test, y_valid, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
)

#------------------#

#Random Forest Algorithm
rf = RandomForestClassifier(
    n_estimators=100, #100 trees in the forest
    random_state=42, #result reproduce 
    class_weight="balanced"  #handles imbalance
)

#RF train 
rf.fit(X_train, y_train)

#RF valid
y_valid_pred = rf.predict(X_valid)

print("Random Forest validation results:")
print(classification_report(y_valid, y_valid_pred))
print("Validation Accuracy:", accuracy_score(y_valid, y_valid_pred))
print("Validation Confusion Matrix:\n", confusion_matrix(y_valid, y_valid_pred))

#RF test
y_test_pred = rf.predict(X_test)

print("Random Forest TEST results:")
print(classification_report(y_test, y_test_pred))
print("Test Accuracy:", accuracy_score(y_test, y_test_pred))
print("Test Confusion Matrix:\n", confusion_matrix(y_test, y_test_pred))

# ROC Curve for Random Forest
y_probs = rf.predict_proba(X_test)[:, 1]

fpr, tpr, thresholds = roc_curve(y_test, y_probs)
roc_auc = auc(fpr, tpr)

print("Random Forest AUC:", roc_auc)

#------------------#

#XGBoost Algorithm
xgb = XGBClassifier(
    n_estimators=100, #100 boost trees
    learning_rate=0.1, #steps for better accuracy
    random_state=42, #result reproduce
    #use_label_encoder=False,
    eval_metric='logloss',  #avoids warning for binary classification
)

#XGBoost train 
xgb.fit(X_train, y_train)

#XGBoost valid
y_valid_pred_xgb = xgb.predict(X_valid)
print("XGBoost validation results:")
print(classification_report(y_valid, y_valid_pred_xgb))
print("Validation Accuracy:", accuracy_score(y_valid, y_valid_pred_xgb))
print("Validation Confusion Matrix:\n", confusion_matrix(y_valid, y_valid_pred_xgb))

#XGBoost test
y_test_pred_xgb = xgb.predict(X_test)
print("XGBoost TEST results:")
print(classification_report(y_test, y_test_pred_xgb))
print("Test Accuracy:", accuracy_score(y_test, y_test_pred_xgb))
print("Test Confusion Matrix:\n", confusion_matrix(y_test, y_test_pred_xgb))

#------------------#

#Dummy baseline
dummy = DummyClassifier(strategy="stratified", random_state=42)
dummy.fit(X_train, y_train)

y_dummy_pred = dummy.predict(X_valid)

print("Dummy validation results:")
print(classification_report(y_valid, y_dummy_pred, zero_division=0))
print("Dummy Accuracy:", accuracy_score(y_valid, y_dummy_pred))

#------------------#

#Class Imbalance Chart
import matplotlib.pyplot as plt
import seaborn as sns

# Set style
sns.set_style("whitegrid")
plt.figure(figsize=(18, 10))

# Chart 1: Class Distribution Pie
plt.subplot(2, 3, 1)
class_counts =  dataset['label'].value_counts().sort_index()

plt.pie(class_counts, 
        labels=['Benign', 'Malicious'],  # 0 first, 1 second
        autopct='%1.1f%%',
        colors=['#51cf66', '#ff6b6b'],
        startangle=90)
plt.title("Class Distribution", fontsize=10, fontweight='bold')
plt.axis('equal')

# Chart 2: Feature Importance
#RF
plt.subplot(2, 3, 2)
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=True)

plt.barh(feature_importance['feature'], feature_importance['importance'], 
         color='#339af0')
plt.title('Random Forest Feature Importance', fontsize=10, fontweight='bold')
plt.xlabel('Importance Score')

#XGBoost
plt.subplot(2, 3, 3)

xgb_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': xgb.feature_importances_
}).sort_values('importance', ascending=True)

plt.barh(xgb_importance['feature'], xgb_importance['importance'], color='#ff7f0e')
plt.title('XGBoost Feature Importance', fontsize=10, fontweight='bold')
plt.xlabel('Importance Score')

# Chart 3: Model Comparison
plt.subplot(2, 3, 4)
models = ['Dummy Baseline', 'Random Forest', 'XGBoost']
colors = ['#ffa94d', '#51cf66', '#339af0']
accuracy = [
    accuracy_score(y_test, dummy.predict(X_test)),
    accuracy_score(y_test, y_test_pred),
    accuracy_score(y_test, y_test_pred_xgb)
]

bars = plt.bar(models, accuracy, color=colors)
plt.ylim(0, 1.1)
plt.title('Model Accuracy Comparison', fontsize=10, fontweight='bold')
plt.ylabel('Accuracy')
plt.xticks(rotation=45)

# Add value labels on bars
for bar, acc in zip(bars, accuracy):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
             f'{acc*100:.0f}%', ha='center', fontweight='bold')

# Chart 4: Confusion Matrix
#RF
plt.subplot(2, 3, 5)
cm = confusion_matrix(y_test, y_test_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious'])
plt.title('Random Forest Confusion Matrix\n(Test Set)', fontsize=10, fontweight='bold')
plt.ylabel('Actual')
plt.xlabel('Predicted')

#XGBoost
plt.subplot(2, 3, 6)
cm_xgb = confusion_matrix(y_test, y_test_pred_xgb)

sns.heatmap(cm_xgb, annot=True, fmt='d', cmap='Oranges',
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious'])

plt.title('XGBoost Confusion Matrix (Test Set)', fontsize=10, fontweight='bold')
plt.ylabel('Actual')
plt.xlabel('Predicted')

plt.tight_layout()
plt.savefig(os.path.join(VISUALIZATION_DIR, 'ml_results_visualization.png'), dpi=300, bbox_inches='tight')
plt.close()
print("✅ Visualization saved as 'ml_results_visualization.png'")

# Correlation Heatmap (sampling)
# Correlation between features

sampled_X = X.sample(n=10000, random_state=42)

plt.figure(figsize=(10, 8))

corr_matrix = sampled_X.corr()

sns.heatmap(
    corr_matrix,
    cmap='coolwarm',
    center=0,
    square=True,
    linewidths=0.5
)

plt.title('Feature Correlation Heatmap', fontsize=16, fontweight='bold')

plt.tight_layout()

plt.savefig(
    os.path.join(VISUALIZATION_DIR, 'feature_correlation.png'),
    dpi=120,
    bbox_inches='tight'
)

plt.close()

#Performance Summary Table
from tabulate import tabulate

# Create summary table
summary_data = [
    ["Dataset Size", f"{len(dataset)} URLs", ""],
    ["Class Split", str(dataset['label'].value_counts().to_dict()), ""],
    ["Train/Val/Test", "70/15/15", "Stratified"],
    ["Random Forest", "Validation Accuracy", f"{accuracy_score(y_valid, y_valid_pred):.4f}"],
    ["Random Forest", "Test Accuracy", f"{accuracy_score(y_test, y_test_pred):.4f}"],
    ["XGBoost", "Validation Accuracy", f"{accuracy_score(y_valid, y_valid_pred_xgb):.4f}"],
    ["XGBoost", "Test Accuracy", f"{accuracy_score(y_test, y_test_pred_xgb):.4f}"]
]

print("\n" + "="*60)
print("📊 ML RESULTS SUMMARY")
print("="*60)
print(tabulate(summary_data, headers=["Metric", "Value", "Score"], 
               tablefmt="grid", numalign="center"))

#Feature DIstribution by Class
# Compare feature distributions for malicious vs benign
fig, axes = plt.subplots(3, 4, figsize=(16, 12))
features_to_plot = ['url_length', 'num_dots', 'has_https', 'has_ip',
    'num_subdirs', 'num_params', 'suspicious_words',
    'special_char_count', 'digits_count', 'entropy',
    'domain_length', 'num_subdomains']

#sampling
sampled_data = dataset.sample(n=10000, random_state=42)

for idx, feature in enumerate(features_to_plot):
    ax = axes[idx//4, idx%4]
    
    # Plot distributions
    malicious_vals = sampled_data[sampled_data['result']==1][feature]
    benign_vals = sampled_data[sampled_data['result']==0][feature]
    
    ax.hist(malicious_vals, bins=30, alpha=0.6, label='Malicious', color='#ff6b6b', density=True)
    ax.hist(benign_vals, bins=30, alpha=0.6, label='Benign', color='#51cf66', density=True)
    
    ax.set_title(feature.replace('_', ' ').title())
    ax.set_xlabel('Value')
    ax.set_ylabel('Density')
    ax.legend()

plt.suptitle('Feature Distributions: Malicious vs Benign URLs', fontsize=16, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(VISUALIZATION_DIR, 'feature_distributions.png'), dpi=150, bbox_inches='tight')
plt.close()

print(f"✅ Visualizations saved to: {VISUALIZATION_DIR}")
print(f"   - ml_results_visualization.png")
print(f"   - feature_correlation.png")  
print(f"   - feature_distributions.png")

#------------------#

import joblib

#Save RF model
joblib.dump(rf, r"D:\UniKL Assignment [new]\UniKL Sem5\FYP 1\Prototype\ML URL Training\ML URL Train\rf_model.pkl")
#Save XGBoost model
joblib.dump(xgb, r"D:\UniKL Assignment [new]\UniKL Sem5\FYP 1\Prototype\ML URL Training\ML URL Train\xgb_model.pkl")
#Save feature
joblib.dump(X.columns.tolist(), r"D:\UniKL Assignment [new]\UniKL Sem5\FYP 1\Prototype\ML URL Training\ML URL Train\features.pkl")

print("✅ Model and features saved")