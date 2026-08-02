from fastapi import FastAPI, HTTPException, Depends, status, Request
from sqlmodel import Session, select
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from database.session import create_tables, get_session
from fastapi.security import OAuth2PasswordRequestForm
from models.patient import Patient, PatientCreate, PatientUpdate
from datetime import datetime

from models.user import (
    User,
    UserCreate,
    UserLogin,
    UserResponse
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_active_user,
     get_current_admin
)
from models.audit import AuditLog
def create_audit_log(
    session: Session,
    user_id: int,
    action: str,
    resource: str,
    resource_id: int | None = None,
    details: str | None = None
):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        details=details
    )

    session.add(audit_log)
    session.commit()
app = FastAPI(
    title="ClinicGuard Patient Management API",
    version="1.0.0",
    description="Secure patient management API with RBAC and rate limiting"
)

limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)

@app.on_event("startup")
def on_startup():
    create_tables()


@app.get("/")
def root():
    return {
        "message": "Welcome to ClinicGuard Patient Management API"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
@app.post("/register")
@limiter.limit("5/minute")
def register(
    request: Request,
    user_data: UserCreate,
    session: Session = Depends(get_session)
):
    existing_user = session.exec(
        select(User).where(
            User.username == user_data.username
        )
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    existing_email = session.exec(
        select(User).where(
            User.email == user_data.email
        )
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    hashed_password = hash_password(
        user_data.password
    )

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        role=user_data.role
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user

@app.post("/login")
@limiter.limit("5/minute")
def login(
     request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.exec(
        select(User).where(
            User.username == form_data.username
        )
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not verify_password(
        form_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive"
        )

    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/me")
def get_me(
    current_user: User = Depends(get_current_active_user)
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role
    }

@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: User = Depends(get_current_admin)
):
    return {
        "message": "Welcome to the admin dashboard",
        "username": current_user.username,
        "role": current_user.role
    }

@app.post("/patients", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")
def create_patient(
    request: Request,
    patient_data: PatientCreate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    patient = Patient(
        first_name=patient_data.first_name,
        last_name=patient_data.last_name,
        date_of_birth=patient_data.date_of_birth,
        phone=patient_data.phone,
        email=patient_data.email,
        address=patient_data.address,
        medical_notes=patient_data.medical_notes,
        doctor_id=patient_data.doctor_id,
        created_by=current_user.id
    )

    session.add(patient)
    session.commit()
    session.refresh(patient)

    create_audit_log(
        session=session,
        user_id=current_user.id,
        action="CREATE",
        resource="patient",
        resource_id=patient.id,
        details="Patient record created"
    )

    return patient
  

@app.get("/patients")
@limiter.limit("30/minute")
def get_patients(
     request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    if current_user.role == "admin":
        patients = session.exec(
            select(Patient)
        ).all()

    elif current_user.role == "doctor":
        patients = session.exec(
            select(Patient).where(
                Patient.doctor_id == current_user.id
            )
        ).all()

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access patient records"
        )

    return patients

@app.get("/patients/{patient_id}")
@limiter.limit("30/minute")
def get_patient(
    request: Request,
    patient_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # Admin can access any patient
    if current_user.role == "admin":
        return patient

    # Doctor can access only their assigned patients
    elif current_user.role == "doctor":
        if patient.doctor_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to access this patient"
            )

        return patient

    # Other roles are not allowed
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access patient records"
        )

@app.put("/patients/{patient_id}")
def update_patient(
    patient_id: int,
    patient_data: PatientUpdate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # Admin can update any patient
    if current_user.role == "admin":
        pass

    # Doctor can update only their assigned patients
    elif current_user.role == "doctor":
        if patient.doctor_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to update this patient"
            )

    # Other roles are not allowed
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update patient records"
        )

    update_data = patient_data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(patient, key, value)

    patient.updated_at = datetime.utcnow()

    session.add(patient)
    session.commit()
    session.refresh(patient)
    create_audit_log(
    session=session,
    user_id=current_user.id,
    action="UPDATE",
    resource="patient",
    resource_id=patient.id,
    details="Patient record updated"
)

    return patient


@app.delete("/patients/{patient_id}")
def delete_patient(
    patient_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # Admin can delete any patient
    if current_user.role == "admin":
        pass

    # Doctor can delete only their assigned patients
    elif current_user.role == "doctor":
        if patient.doctor_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to delete this patient"
            )

    # Other roles cannot delete patients
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete patient records"
        )

    session.delete(patient)
    session.commit()
    create_audit_log(
    session=session,
    user_id=current_user.id,
    action="DELETE",
    resource="patient",
    resource_id=patient_id,
    details="Patient record deleted"
)


    return {
        "message": "Patient deleted successfully",
        "patient_id": patient_id
    }