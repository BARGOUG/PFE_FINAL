import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
from imblearn.over_sampling import SMOTE
from sklearn.neural_network import MLPClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import joblib  # For saving models

# Step 1: Load the Dataset
# Replace the path with the actual path to your CSV file
df_clean = pd.read_csv(r"C:\Users\IBRAG9\Desktop\PFE_final\cleaned_api_calls_dataset.csv")

# Ensure no rows have missing values in 'api_calls'
df_clean = df_clean.dropna(subset=["api_calls"])

# Features and labels
X = df_clean["api_calls"]  # Raw API calls (with prefixes)
y = df_clean["label"]      # Labels (0 for goodware, 1 for malware)

# Step 2: Feature Extraction (Bag of Words)
bow = CountVectorizer(max_features=5000, token_pattern=r'\b\w+\b')  # Limit to top 5000 features
X_bow = bow.fit_transform(X)

# Save the Bag of Words vectorizer
joblib.dump(bow, "bow_vectorizer.joblib")
print("Bag of Words vectorizer saved as 'bow_vectorizer.joblib'.")

# Get the feature names (API calls)
feature_names = bow.get_feature_names_out()

# Print the number of features
print(f"Number of features (unique API calls): {len(feature_names)}")

# Step 3: Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X_bow, y, test_size=0.2, random_state=42, stratify=y
)

# Step 4: Handle Imbalanced Data with SMOTE
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

# Step 5: Train and Evaluate MLP Neural Network
mlp = MLPClassifier(
    hidden_layer_sizes=(100, 100, 100, 100, 100),  # 5 hidden layers, each with 100 neurons
    activation='relu',                            # Activation function
    solver='adam',                                # Optimization algorithm
    max_iter=300,                                 # Maximum number of iterations
    random_state=42
)

# Train the MLP model
mlp.fit(X_train_resampled, y_train_resampled)

# Save the trained MLP model
joblib.dump(mlp, "mlp_model.joblib")
print("Trained MLP model saved as 'mlp_model.joblib'.")

# Make predictions on the test set
y_pred = mlp.predict(X_test)
y_proba = mlp.predict_proba(X_test)[:, 1]  # Probabilities for ROC AUC

# Evaluate the model
print("\nMLP Neural Network Performance:")
print(classification_report(y_test, y_pred))
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall: {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

# Step 6: Visualize Confusion Matrix
def plot_confusion_matrix(y_true, y_pred):
    """
    Plots the confusion matrix for the given predictions.
    
    Parameters:
        y_true (array-like): True labels.
        y_pred (array-like): Predicted labels.
    """
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.show()

# Example: Plot the confusion matrix
plot_confusion_matrix(y_test, y_pred)
