from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# 1. إنشاء السيرفر الأوتوماتيكي
app = FastAPI(title="DEPI CyberSecurity Automated ML Engine")

# 2. تحميل الموديل الذكي والمحفوظ بتاعك
model_path = r'E:\depi project\my file\security_rf_model.pkl'
try:
    model = joblib.load(model_path)
    print("🧠 ML Model Loaded successfully into the API!")
except Exception as e:
    print(f"❌ Error loading model: {e}")

# 3. تحديد شكل البيانات (المتغيرات اللي زمايلك هيبعتوها من الـ Backend)
class NetworkPacketInput(BaseModel):
    Init_Bwd_Win_Bytes: float
    Fwd_IAT_Min: float
    Init_Fwd_Win_Bytes: float
    Fwd_Seg_Size_Min: float
    Packet_Length_Min: float
    Fwd_Packet_Length_Min: float
    Bwd_IAT_Min: float
    PSH_Flag_Count: float
    Bwd_Packet_Length_Min: float
    Protocol: float

# 4. نقطة الاستقبال والتوقع الأوتوماتيكية
@app.post("/predict")
def predict_traffic(packet: NetworkPacketInput):
    try:
        # تحويل البيانات القادمة إلى قاموس بأسماء الأعمدة الأصلية (بالمسافات) زي الداتا سيت
        features_dict = {
            'Init Bwd Win Bytes': [packet.Init_Bwd_Win_Bytes],
            'Fwd IAT Min': [packet.Fwd_IAT_Min],
            'Init Fwd Win Bytes': [packet.Init_Fwd_Win_Bytes],
            'Fwd Seg Size Min': [packet.Fwd_Seg_Size_Min],
            'Packet Length Min': [packet.Packet_Length_Min],
            'Fwd Packet Length Min': [packet.Fwd_Packet_Length_Min],
            'Bwd IAT Min': [packet.Bwd_IAT_Min],
            'PSH Flag Count': [packet.PSH_Flag_Count],
            'Bwd Packet Length Min': [packet.Bwd_Packet_Length_Min],
            'Protocol': [packet.Protocol]
        }
        
        # تحويلها لـ DataFrame عشان الموديل يقرأ ترتيب الأسماء صح
        input_df = pd.DataFrame(features_dict)
        
        # عمل الـ Scaling المظبوط للداتا
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(input_df)
        
        # تشغيل الموديل فوراً لتحديد نوع الحركة
        prediction = model.predict(scaled_features)[0]
        
        # الرد الأوتوماتيكي النهائي اللي هيروح للـ Dashboard
        return {
            "status": "success",
            "prediction": str(prediction),
            "is_malicious": bool(prediction != "Benign")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))