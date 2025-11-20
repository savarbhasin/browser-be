from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Report
from ..schemas import ReportCreate, ReportResponse
from ..rate_limit import limiter, RATE_LIMITS
from typing import List
router = APIRouter()

@router.post('/', response_model=ReportResponse)
@limiter.limit(RATE_LIMITS['report_create'])
def create_report(request: Request, response: Response, report_data: ReportCreate, db: Session=Depends(get_db)):
    new_report = Report(url=report_data.url, type=report_data.type, description=report_data.description)
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

@router.get('/', response_model=List[ReportResponse])
@limiter.limit(RATE_LIMITS['report_read'])
def list_reports(request: Request, response: Response, skip: int=0, limit: int=100, db: Session=Depends(get_db)):
    reports = db.query(Report).order_by(Report.created_at.desc()).offset(skip).limit(limit).all()
    return reports

@router.get('/{report_id}', response_model=ReportResponse)
@limiter.limit(RATE_LIMITS['report_read'])
def get_report(request: Request, response: Response, report_id: str, db: Session=Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    return report