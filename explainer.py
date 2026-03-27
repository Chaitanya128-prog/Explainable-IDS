import shap
import pandas as pd

class SHAPExplainer:
    def __init__(self, model):
        # Isolation Forest is tree-based, so TreeExplainer is fast and exact
        self.explainer = shap.TreeExplainer(model)
        
    def explain_instance(self, instance_df: pd.DataFrame):
        """
        Generates local SHAP explanations for a single instance.
        Returns a sorted dictionary mapping feature names to their SHAP values.
        """
        shap_values = self.explainer.shap_values(instance_df)
        
        feature_names = instance_df.columns.tolist()
        
        # Extract the 1D array of SVs robustly across different SHAP versions
        try:
            if hasattr(shap_values, 'values'):
                sv = shap_values.values[0]
            elif isinstance(shap_values, list):
                sv = shap_values[0][0]
            else:
                sv = shap_values[0]
        except Exception:
            sv = [0] * len(feature_names)
            
        explanations = {feature_names[i]: sv[i] for i in range(len(feature_names))}
        
        # Sort by absolute impact (the most important features pushing the score in either direction)
        sorted_explanations = dict(sorted(explanations.items(), key=lambda item: abs(item[1]), reverse=True))
        return sorted_explanations
