"""
Appointments API Router (v2)
Routes: /api/appointments/*

Full CRUD operations for appointments with role-based access.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel

from config.database import get_db
from models import User, UserRole, Appointment, AppointmentStatus, Patient, Doctor
from utils.security import get_current_user

router = APIRouter(prefix="/api/appointments", tags=["Appointments"])


# ============ SCHEMAS ============

class AppointmentCreate(BaseModel):
    patient_id: Optional[int] = None
    doctor_id: int
    appointment_date: Optional[str] = None  # ISO datetime string
    scheduled_time: Optional[str] = None    # Alias for appointment_date
    reason: Optional[str] = "Consultation"
    notes: Optional[str] = None
    duration_minutes: Optional[int] = 30


class AppointmentUpdate(BaseModel):
    appointment_date: Optional[str] = None
    reason: Optional[str] = None
    notes: Optional[str] = None
    duration_minutes: Optional[int] = None


class AppointmentStatusUpdate(BaseModel):
    status: str  # scheduled, confirmed, completed, cancelled
    cancellation_reason: Optional[str] = None


class AppointmentResponse(BaseModel):
    id: int
    patient_id: int
    patient_name: Optional[str] = None
    doctor_id: int
    doctor_name: Optional[str] = None
    appointment_date: str
    scheduled_time: Optional[str] = None  # Alias
    reason: str
    status: str
    notes: Optional[str] = None
    duration_minutes: int
    cancellation_reason: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class AppointmentsListResponse(BaseModel):
    appointments: List[AppointmentResponse]
    total: int
    page: int
    limit: int
    total_pages: int


# ============ HELPER FUNCTIONS ============

def appointment_to_response(apt: Appointment, db: Session) -> dict:
    """Convert Appointment model to response format"""
    # Get patient name - appointments reference users.id, not patients.id
    patient = db.query(User).filter(User.id == apt.patient_id).first()
    doctor = db.query(User).filter(User.id == apt.doctor_id).first()
    
    apt_date = apt.appointment_date.isoformat() if apt.appointment_date else None
    
    return {
        "id": apt.id,
        "patient_id": apt.patient_id,
        "patient_name": patient.name if patient else f"Patient #{apt.patient_id}",
        "doctor_id": apt.doctor_id,
        "doctor_name": doctor.name if doctor else f"Doctor #{apt.doctor_id}",
        "appointment_date": apt_date,
        "scheduled_time": apt_date,  # Alias for frontend compatibility
        "reason": apt.reason if apt.reason else "Consultation",
        "status": apt.status.value if apt.status else "scheduled",
        "notes": apt.notes,
        "duration_minutes": apt.duration_minutes or 30,
        "cancellation_reason": apt.cancellation_reason,
        "created_at": apt.created_at.isoformat() if apt.created_at else None,
        "updated_at": apt.updated_at.isoformat() if apt.updated_at else None
    }


# ============ ENDPOINTS ============

@router.get("", response_model=AppointmentsListResponse)
@router.get("/", response_model=AppointmentsListResponse)
async def get_appointments(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = None,
    date: Optional[str] = None,
    doctor_id: Optional[int] = None,
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get appointments with filters (role-based).
    
    GET /api/appointments?page=1&limit=10&status=scheduled
    """
    query = db.query(Appointment)
    
    # Role-based filtering: appointments uses users.id for patient_id and doctor_id
    if current_user.role == UserRole.PATIENT:
        query = query.filter(Appointment.patient_id == current_user.id)
    
    elif current_user.role == UserRole.DOCTOR:
        query = query.filter(Appointment.doctor_id == current_user.id)
    
    # Apply filters
    if status:
        try:
            status_enum = AppointmentStatus(status)
            query = query.filter(Appointment.status == status_enum)
        except ValueError:
            pass
    
    if date:
        try:
            filter_date = datetime.fromisoformat(date).date()
            query = query.filter(func.date(Appointment.appointment_date) == filter_date)
        except ValueError:
            pass
    
    if doctor_id and current_user.role in [UserRole.ADMIN, UserRole.SUPERADMIN, UserRole.STAFF]:
        query = query.filter(Appointment.doctor_id == doctor_id)
    
    if patient_id and current_user.role in [UserRole.ADMIN, UserRole.SUPERADMIN, UserRole.STAFF, UserRole.DOCTOR]:
        query = query.filter(Appointment.patient_id == patient_id)
    
    total = query.count()
    skip = (page - 1) * limit
    appointments = query.order_by(Appointment.appointment_date.desc()).offset(skip).limit(limit).all()
    
    return {
        "appointments": [appointment_to_response(a, db) for a in appointments],
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit if total > 0 else 0
    }


@router.get("/my-appointments", response_model=AppointmentsListResponse)
async def get_my_appointments(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get appointments for current user (patient or doctor).
    
    GET /api/appointments/my-appointments
    """
    query = db.query(Appointment)
    
    # appointments table uses users.id directly
    if current_user.role == UserRole.PATIENT:
        query = query.filter(Appointment.patient_id == current_user.id)
    elif current_user.role == UserRole.DOCTOR:
        query = query.filter(Appointment.doctor_id == current_user.id)
    else:
        # Admin/Staff see all
        pass
    
    if status:
        try:
            status_enum = AppointmentStatus(status)
            query = query.filter(Appointment.status == status_enum)
        except ValueError:
            pass
    
    total = query.count()
    skip = (page - 1) * limit
    appointments = query.order_by(Appointment.appointment_date.desc()).offset(skip).limit(limit).all()
    
    return {
        "appointments": [appointment_to_response(a, db) for a in appointments],
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit if total > 0 else 0
    }


@router.get("/{appointment_id}")
async def get_appointment(
    appointment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a specific appointment.
    
    GET /api/appointments/{appointment_id}
    """
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check access permissions
    if current_user.role == UserRole.PATIENT:
        if appointment.patient_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    elif current_user.role == UserRole.DOCTOR:
        if appointment.doctor_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    return appointment_to_response(appointment, db)


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_appointment(
    data: AppointmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new appointment.
    
    POST /api/appointments
    """
    # Use appointment_date or scheduled_time (alias)
    date_str = data.appointment_date or data.scheduled_time
    if not date_str:
        raise HTTPException(status_code=400, detail="appointment_date or scheduled_time is required")
    
    # The doctor_id in the request refers to doctor.id (from doctors table)
    # But appointments.doctor_id references users.id
    # So we need to find the user_id from doctors table
    doctor = db.query(Doctor).filter(Doctor.id == data.doctor_id).first()
    if not doctor:
        # Maybe doctor_id is actually user_id? Try that
        doctor = db.query(Doctor).filter(Doctor.user_id == data.doctor_id).first()
        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")
    
    if not doctor.is_available:
        raise HTTPException(status_code=400, detail="Doctor is not available")
    
    # Get doctor's user_id for appointment
    doctor_user_id = doctor.user_id
    
    # Determine patient_id (which is users.id)
    if current_user.role == UserRole.PATIENT:
        patient_user_id = current_user.id
    elif data.patient_id:
        patient_user_id = data.patient_id
    else:
        raise HTTPException(status_code=400, detail="patient_id is required")
    
    # Parse scheduled time
    try:
        appointment_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use ISO format.")
    
    new_appointment = Appointment(
        patient_id=patient_user_id,
        doctor_id=doctor_user_id,
        appointment_date=appointment_date,
        reason=data.reason or "Consultation",
        duration_minutes=data.duration_minutes or 30,
        notes=data.notes,
        status=AppointmentStatus.SCHEDULED,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(new_appointment)
    db.commit()
    db.refresh(new_appointment)
    
    return appointment_to_response(new_appointment, db)


@router.put("/{appointment_id}")
async def update_appointment(
    appointment_id: int,
    data: AppointmentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update an appointment.
    
    PUT /api/appointments/{appointment_id}
    """
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check permissions
    if current_user.role == UserRole.PATIENT:
        if appointment.patient_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = data.model_dump(exclude_unset=True)
    
    if "appointment_date" in update_data and update_data["appointment_date"]:
        try:
            update_data["appointment_date"] = datetime.fromisoformat(
                update_data["appointment_date"].replace('Z', '+00:00')
            )
        except ValueError:
            del update_data["appointment_date"]
    
    for field, value in update_data.items():
        if hasattr(appointment, field):
            setattr(appointment, field, value)
    
    appointment.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(appointment)
    
    return appointment_to_response(appointment, db)


@router.patch("/{appointment_id}/status")
async def update_appointment_status(
    appointment_id: int,
    data: AppointmentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update appointment status.
    
    PATCH /api/appointments/{appointment_id}/status
    """
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check permissions based on action
    if data.status == "cancelled":
        # Anyone involved can cancel
        if current_user.role == UserRole.PATIENT and appointment.patient_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    elif data.status in ["confirmed", "completed"]:
        # Only doctor or admin can confirm/complete
        if current_user.role not in [UserRole.ADMIN, UserRole.SUPERADMIN, UserRole.STAFF, UserRole.DOCTOR]:
            raise HTTPException(status_code=403, detail="Not authorized to change status")
        if current_user.role == UserRole.DOCTOR and appointment.doctor_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        new_status = AppointmentStatus(data.status)
        appointment.status = new_status
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {data.status}")
    
    if data.status == "cancelled" and data.cancellation_reason:
        appointment.cancellation_reason = data.cancellation_reason
    
    appointment.updated_at = datetime.utcnow()
    db.commit()
    
    return {
        "id": appointment.id,
        "status": appointment.status.value,
        "message": f"Appointment {data.status} successfully"
    }


@router.delete("/{appointment_id}")
async def cancel_appointment(
    appointment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancel an appointment.
    
    DELETE /api/appointments/{appointment_id}
    """
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check permissions
    if current_user.role == UserRole.PATIENT:
        if appointment.patient_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    appointment.status = AppointmentStatus.CANCELLED
    appointment.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Appointment cancelled successfully"}
