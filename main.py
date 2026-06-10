from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./b2b.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    stir = Column(String, unique=True)
    phone = Column(String)
    address = Column(String)
    bonus_balance = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    orders = relationship("Order", back_populates="company")
    bonuses = relationship("Bonus", back_populates="company")

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    amount = Column(Float)
    description = Column(Text)
    status = Column(String, default="completed")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    company = relationship("Company", back_populates="orders")
    bonuses = relationship("Bonus", back_populates="order")

class Bonus(Base):
    __tablename__ = "bonuses"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=True)
    amount = Column(Float)
    description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    company = relationship("Company", back_populates="bonuses")
    order = relationship("Order", back_populates="bonuses")

class Promotion(Base):
    __tablename__ = "promotions"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text)
    discount_percent = Column(Float)
    bonus_percent = Column(Float, default=5.0)
    start_date = Column(DateTime(timezone=True))
    end_date = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
SECRET_KEY = os.getenv("SECRET_KEY", "b2b-secret-key-2024")
ALGORITHM = "HS256"

def create_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(hours=24)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token yaroqsiz")

app = FastAPI(title="B2B Aksiya va Bonuslar Tizimi", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str
    is_admin: Optional[bool] = False

class CompanyCreate(BaseModel):
    name: str
    stir: str
    phone: str
    address: str

class OrderCreate(BaseModel):
    company_id: int
    amount: float
    description: str

class PromotionCreate(BaseModel):
    title: str
    description: str
    discount_percent: float
    bonus_percent: Optional[float] = 5.0
    start_date: datetime
    end_date: datetime

@app.get("/")
def root():
    return {"message": "B2B Tizimi ishlayapti!"}

@app.post("/api/auth/register")
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email allaqachon royxatdan otgan")
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=pwd_context.hash(user_data.password),
        is_admin=user_data.is_admin if user_data.is_admin is not None else False
    )
    db.add(user)
    db.commit()
    return {"message": "Muvaffaqiyatli royxatdan otildi"}

@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Email yoki parol notogri")
    token = create_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer", "is_admin": user.is_admin, "full_name": user.full_name}

@app.get("/api/auth/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email, "full_name": current_user.full_name, "is_admin": current_user.is_admin}

@app.get("/api/companies/")
def get_companies(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Company).all()

@app.post("/api/companies/")
def create_company(data: CompanyCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if db.query(Company).filter(Company.stir == data.stir).first():
        raise HTTPException(status_code=400, detail="Bu STIR bilan kompaniya mavjud")
    company = Company(name=data.name, stir=data.stir, phone=data.phone, address=data.address)
    db.add(company)
    db.commit()
    db.refresh(company)
    return company

@app.delete("/api/companies/{company_id}")
def delete_company(company_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Kompaniya topilmadi")
    db.delete(company)
    db.commit()
    return {"message": "Kompaniya ochirildi"}

@app.get("/api/orders/")
def get_orders(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    orders = db.query(Order).all()
    return [{"id": o.id, "company_id": o.company_id, "company_name": o.company.name if o.company else "",
             "amount": o.amount, "description": o.description, "status": o.status, "created_at": o.created_at} for o in orders]

@app.post("/api/orders/")
def create_order(data: OrderCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    company = db.query(Company).filter(Company.id == data.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Kompaniya topilmadi")
    order = Order(company_id=data.company_id, amount=data.amount, description=data.description)
    db.add(order)
    db.commit()
    db.refresh(order)
    now = datetime.utcnow()
    promo = db.query(Promotion).filter(Promotion.is_active == True, Promotion.start_date <= now, Promotion.end_date >= now).first()
    bonus_percent = promo.bonus_percent if promo else 5.0
    bonus_amount = data.amount * (bonus_percent / 100)
    bonus = Bonus(company_id=data.company_id, order_id=order.id, amount=bonus_amount,
                  description="Buyurtma #" + str(order.id) + " uchun " + str(bonus_percent) + "% bonus")
    db.add(bonus)
    company.bonus_balance += bonus_amount
    db.commit()
    return {"order_id": order.id, "bonus_added": bonus_amount, "bonus_percent": bonus_percent}

@app.get("/api/bonuses/")
def get_bonuses(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    bonuses = db.query(Bonus).all()
    return [{"id": b.id, "company_id": b.company_id, "company_name": b.company.name if b.company else "",
             "order_id": b.order_id, "amount": b.amount, "description": b.description, "created_at": b.created_at} for b in bonuses]

@app.get("/api/promotions/")
def get_promotions(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Promotion).all()

@app.post("/api/promotions/")
def create_promotion(data: PromotionCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    promo = Promotion(
        title=data.title, description=data.description,
        discount_percent=data.discount_percent,
        bonus_percent=data.bonus_percent if data.bonus_percent else 5.0,
        start_date=data.start_date, end_date=data.end_date
    )
    db.add(promo)
    db.commit()
    db.refresh(promo)
    return promo

@app.put("/api/promotions/{promo_id}/toggle")
def toggle_promotion(promo_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    promo = db.query(Promotion).filter(Promotion.id == promo_id).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Aksiya topilmadi")
    promo.is_active = not promo.is_active
    db.commit()
    return {"message": "Aksiya holati ozgartirildi"}

@app.delete("/api/promotions/{promo_id}")
def delete_promotion(promo_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    promo = db.query(Promotion).filter(Promotion.id == promo_id).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Aksiya topilmadi")
    db.delete(promo)
    db.commit()
    return {"message": "Aksiya ochirildi"}

@app.get("/api/reports/dashboard")
def get_dashboard(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    total_companies = db.query(func.count(Company.id)).scalar()
    total_orders = db.query(func.count(Order.id)).scalar()
    total_revenue = db.query(func.sum(Order.amount)).scalar() or 0
    total_bonuses = db.query(func.sum(Bonus.amount)).scalar() or 0
    active_promotions = db.query(func.count(Promotion.id)).filter(Promotion.is_active == True).scalar()
    top_companies = db.query(Company.id, Company.name, Company.bonus_balance,
        func.sum(Order.amount).label("total_spent")).join(Order, Order.company_id == Company.id, isouter=True)\
        .group_by(Company.id).order_by(func.sum(Order.amount).desc()).limit(5).all()
    return {
        "total_companies": total_companies, "total_orders": total_orders,
        "total_revenue": round(total_revenue, 2), "total_bonuses_given": round(total_bonuses, 2),
        "active_promotions": active_promotions,
        "top_companies": [{"id": c.id, "name": c.name, "bonus_balance": c.bonus_balance, "total_spent": c.total_spent or 0} for c in top_companies]
    }
