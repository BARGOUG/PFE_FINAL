import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier  # Import MLPClassifier
from imblearn.over_sampling import SMOTE
import joblib
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)

# Step 1: Load the Cleaned Dataset
df_clean = pd.read_csv("cleaned_api_calls_dataset.csv")

# Ensure no rows have missing values in 'api_calls'
df_clean = df_clean.dropna(subset=["api_calls"])

# Step 2: Define the Cleaning Function
def clean_api_calls(api_sequence):
    # Split each API call by '.' and keep only the last part
    cleaned_sequence = " ".join([call.split('.')[-1] for call in api_sequence.split()])
    return cleaned_sequence

# Apply the cleaning function
df_clean.loc[:, "api_calls"] = df_clean["api_calls"].apply(clean_api_calls)

# Features and labels
X = df_clean["api_calls"]  # Cleaned API calls
y = df_clean["label"]      # Labels (0 for goodware, 1 for malware)

# Step 3: Feature Extraction (TF-IDF)
tfidf = TfidfVectorizer(max_features=5000, token_pattern=r'\b\w+\b')  # Limit to top 5000 features
X_tfidf = tfidf.fit_transform(X)

# Step 4: Split the Data into Training and Testing Sets
X_train, X_test, y_train, y_test = train_test_split(
    X_tfidf, y, test_size=0.2, random_state=42, stratify=y
)

# Step 5: Apply SMOTE to Balance the Training Set
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

# Verify the Class Distribution After SMOTE
print("\nClass Distribution After SMOTE:")
print(pd.Series(y_train_resampled).value_counts())

# Step 6: Train an MLP Neural Network Model
mlp = MLPClassifier(
    hidden_layer_sizes=(100,),  # Single hidden layer with 100 neurons
    activation="relu",          # Activation function
    solver="adam",              # Optimization algorithm
    max_iter=200,               # Maximum number of iterations
    random_state=42             # Reproducibility
)
mlp.fit(X_train_resampled, y_train_resampled)

# Evaluate the Model on the Test Set
y_pred = mlp.predict(X_test)
y_probs = mlp.predict_proba(X_test)[:, 1]  # Probabilities for class 1 (malware)

# Classification Report and Confusion Matrix
print("\nClassification Report (Test Set):\n")
print(classification_report(y_test, y_pred, zero_division=0))

print("Confusion Matrix (Test Set):\n")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Additional Metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
roc_auc = roc_auc_score(y_test, y_probs)

print("\nAdditional Evaluation Metrics:")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-Score: {f1:.4f}")
print(f"ROC-AUC Score: {roc_auc:.4f}")

# Save the trained model and vectorizer
joblib.dump(mlp, "mlp_neural_network_model.pkl")  # Save the MLP model
joblib.dump(tfidf, "tfidf_vectorizer.pkl")        # Save the TF-IDF vectorizer

