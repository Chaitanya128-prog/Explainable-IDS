import shap
import pandas as pd

class SHAPExplainer:
    def __init__(self):
        self.explainer = None
        
    def initialize(self, isolation_forest_model):
        self.explainer = shap.TreeExplainer(isolation_forest_model)
        
    def explain_instance(self, instance_df: pd.DataFrame):
        if not self.explainer:
            return {}
            
        shap_values = self.explainer.shap_values(instance_df)
        feature_names = instance_df.columns.tolist()
        
        try:
            if hasattr(shap_values, 'values'):
                sv = shap_values.values[0]
            elif isinstance(shap_values, list):
                sv = shap_values[0][0]
            else:
                sv = shap_values[0]
        except Exception:
            sv = [0] * len(feature_names)
            
        # Convert to float for JSON serialization
        explanations = {feature_names[i]: float(sv[i]) for i in range(len(feature_names))}
        sorted_explanations = dict(sorted(explanations.items(), key=lambda item: abs(item[1]), reverse=True))
        return sorted_explanations

explainer_engine = SHAPExplainer()
