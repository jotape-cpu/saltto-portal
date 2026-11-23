import os
import re
import json
import hmac
import time
import base64
import hashlib
import secrets
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session
from database import engine, Base, get_db, SessionLocal
from models import (
    User, Turma, MatriculaTurma, Horario, Frequencia,
    Atividade, EntregaAtividade, Atestado, Requerimento,
    EventoCalendario, Aviso, AuditLog
)

Base.metadata.create_all(bind=engine)

PASTAS_UPLOAD = ("atividades", "entregas", "atestados")
for _pasta in PASTAS_UPLOAD:
    os.makedirs(os.path.join("uploads", _pasta), exist_ok=True)

app = FastAPI(title="Saltto", description="Plataforma Acadêmica Institucional")

SECRET_KEY = os.getenv("SECRET_KEY", "saltto-secret-key-troque-em-producao")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_SECONDS = 86400
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
PBKDF2_ITERATIONS = 100000

ROLES = ("admin", "professor", "aluno")
PADROES_ID = {
    "admin": re.compile(r"^ADM-\d{4}-\d{4}$"),
    "professor": re.compile(r"^PROF-\d{4}-\d{4}$"),
    "aluno": re.compile(r"^\d{8}$"),
}
FORMATO_ID = {
    "admin": "ADM-AAAA-XXXX (ex: ADM-2026-0001)",
    "professor": "PROF-AAAA-XXXX (ex: PROF-2026-0001)",
    "aluno": "8 dígitos AAAAXXXX (ex: 20261064)",
}
TIPOS_REQUERIMENTO = (
    "Segunda Chamada",
    "Revisão de Nota",
    "Carteira Estudantil",
    "Aproveitamento de Disciplina",
    "Trancamento",
)
STATUS_REQUERIMENTO = ("Em Análise", "Deferido", "Indeferido")
STATUS_ATESTADO = ("Pendente", "Deferido", "Indeferido")
DIAS_SEMANA = ("Segunda-feira", "Terça-feira", "Quarta-feira", "Quinta-feira", "Sexta-feira", "Sábado")
TIPOS_ATIVIDADE = ("Atividade", "Material")
TIPOS_EVENTO_PROFESSOR = ("Prova", "Atividade")
REGEX_HORA = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def agora(formato: str = "%d/%m/%Y %H:%M") -> str:
    return datetime.now().strftime(formato)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_session_token(user_id: int, role: str) -> str:
    payload = json.dumps({"user_id": user_id, "role": role, "exp": int(time.time()) + SESSION_SECONDS}).encode()
    b64 = base64.urlsafe_b64encode(payload).decode()
    sig = hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def decode_session_token(token: str) -> Optional[dict]:
    try:
        b64, sig = token.split(".")
        expected = hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(b64.encode()).decode())
        if data.get("exp", 0) < int(time.time()):
            return None
        return data
    except Exception:
        return None


def definir_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        key="saltto_session",
        value=create_session_token(user.id, user.role),
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=SESSION_SECONDS
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("saltto_session")
    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado")
    data = decode_session_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")
    user = db.query(User).filter(User.id == data["user_id"], User.ativo == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return user


def require_role(role: str):
    def checker(user: User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(status_code=403, detail="Acesso negado para este perfil")
        return user
    return checker


def auditar(db: Session, ator: str, acao: str, detalhes: str = "") -> None:
    db.add(AuditLog(ator=ator, acao=acao, detalhes=detalhes, data_hora=agora("%d/%m/%Y %H:%M:%S")))


def normalizar_username(valor: str) -> str:
    valor = (valor or "").strip()
    return valor if valor.isdigit() else valor.upper()


def gerar_codigo_ativacao() -> str:
    return secrets.token_hex(3).upper()


def gerar_id(role: str, db: Session) -> str:
    ano = datetime.now().year
    if role == "aluno":
        prefixo = str(ano)
        usados = db.query(User.username).filter(User.role == "aluno", User.username.like(f"{prefixo}%")).all()
        numeros = [int(u[0][4:]) for u in usados if PADROES_ID["aluno"].match(u[0])]
        proximo = (max(numeros) + 1) if numeros else 1
        if proximo > 9999:
            raise HTTPException(status_code=400, detail="Limite de matrículas do ano atingido")
        return f"{prefixo}{proximo:04d}"
    sigla = "ADM" if role == "admin" else "PROF"
    chave = f"{sigla}-{ano}-"
    usados = db.query(User.username).filter(User.username.like(f"{chave}%")).all()
    numeros = [int(u[0][len(chave):]) for u in usados if PADROES_ID[role].match(u[0])]
    proximo = (max(numeros) + 1) if numeros else 1
    if proximo > 9999:
        raise HTTPException(status_code=400, detail="Limite de IDs do ano atingido")
    return f"{chave}{proximo:04d}"


def seed_database():
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        admin = User(
            username="ADM-2026-0001",
            nome="Secretaria Acadêmica Saltto",
            email="secretaria@saltto.edu.br",
            role="admin",
            curso="Administração Institucional",
            password_hash=hash_password("admin123"),
            codigo_ativacao=gerar_codigo_ativacao(),
            primeiro_acesso=False
        )
        prof = User(
            username="PROF-2026-0001",
            nome="Prof. Dr. Carlos Mendes",
            email="carlos.mendes@saltto.edu.br",
            role="professor",
            curso="Computação e Inteligência Artificial",
            password_hash=hash_password("prof123"),
            codigo_ativacao=gerar_codigo_ativacao(),
            primeiro_acesso=False
        )
        aluno = User(
            username="20261064",
            nome="João Pedro Leal",
            email="joao.leal@aluno.saltto.edu.br",
            role="aluno",
            curso="Técnico Integrado em Informática / IA",
            campus="Campus Teresina Central",
            password_hash=hash_password("aluno123"),
            codigo_ativacao=gerar_codigo_ativacao(),
            primeiro_acesso=False
        )
        db.add_all([admin, prof, aluno])
        db.commit()
        db.refresh(admin)
        db.refresh(prof)
        db.refresh(aluno)

        t1 = Turma(codigo="INF01", nome="Inteligência Artificial e Machine Learning", carga_horaria=80, periodo="2026.2", professor_id=prof.id)
        t2 = Turma(codigo="INF02", nome="Desenvolvimento Web Full-Stack", carga_horaria=80, periodo="2026.2", professor_id=prof.id)
        db.add_all([t1, t2])
        db.commit()
        db.refresh(t1)
        db.refresh(t2)

        db.add_all([
            MatriculaTurma(aluno_id=aluno.id, turma_id=t1.id, nota1=9.2, nota2=9.5, status="Aprovado"),
            MatriculaTurma(aluno_id=aluno.id, turma_id=t2.id, nota1=8.8, nota2=9.0, status="Aprovado"),
            Horario(turma_id=t1.id, dia_semana="Segunda-feira", hora_inicio="08:00", hora_fim="10:00", sala="Lab. Informática 03"),
            Horario(turma_id=t2.id, dia_semana="Terça-feira", hora_inicio="08:00", hora_fim="10:00", sala="Lab. Informática 01"),
            Frequencia(turma_id=t1.id, aluno_id=aluno.id, data="2026-11-16", presente=True),
            Frequencia(turma_id=t2.id, aluno_id=aluno.id, data="2026-11-17", presente=True),
            Atividade(
                turma_id=t1.id,
                titulo="Pipeline de Classificação Supervisionada",
                descricao="Implementar modelos de classificação com random_state=64 e enviar o relatório.",
                tipo="Atividade",
                data_entrega="2026-11-25",
                criado_em="2026-11-17"
            ),
            EventoCalendario(
                turma_id=t1.id,
                titulo="Atividade: Pipeline de Classificação Supervisionada",
                tipo="Atividade",
                data="2026-11-25",
                descricao="Implementar modelos de classificação com random_state=64 e enviar o relatório."
            ),
            EventoCalendario(
                turma_id=t1.id,
                titulo="Avaliação Bimestral - Inteligência Artificial",
                tipo="Prova",
                data="2026-11-28",
                descricao="Prova prática em laboratório cobrindo regressão e árvores de decisão."
            ),
            EventoCalendario(
                turma_id=None,
                titulo="Renovação de Matrícula 2027.1",
                tipo="Institucional",
                data="2026-12-01",
                descricao="Abertura do período de confirmação de matrícula no portal Saltto."
            ),
            Aviso(
                autor_id=admin.id,
                turma_id=None,
                titulo="Bem-vindos ao Portal Saltto",
                conteudo="O portal acadêmico está disponível para consulta de notas, frequência, atividades, requerimentos e declarações.",
                criado_em=agora()
            ),
            AuditLog(ator="Sistema", acao="Inicialização", detalhes="Banco de dados populado com dados de demonstração", data_hora=agora("%d/%m/%Y %H:%M:%S"))
        ])
        db.commit()
    finally:
        db.close()


seed_database()


class LoginPayload(BaseModel):
    username: str
    password: str


class PrimeiroAcessoPayload(BaseModel):
    username: str
    codigo_ativacao: str
    password: str
    confirmar_password: str


class AlterarSenhaPayload(BaseModel):
    senha_atual: str
    nova_senha: str
    confirmar_senha: str


class CreateUserPayload(BaseModel):
    username: Optional[str] = ""
    nome: str
    email: Optional[str] = ""
    role: str
    curso: Optional[str] = ""
    campus: Optional[str] = ""
    password: Optional[str] = ""


class CreateTurmaPayload(BaseModel):
    codigo: str
    nome: str
    carga_horaria: int
    periodo: str
    professor_id: int


class MatricularTurmaPayload(BaseModel):
    aluno_id: int
    turma_id: int


class HorarioPayload(BaseModel):
    turma_id: int
    dia_semana: str
    hora_inicio: str
    hora_fim: str
    sala: str


class FrequenciaItem(BaseModel):
    aluno_id: int
    presente: bool


class FrequenciaBatchPayload(BaseModel):
    turma_id: int
    data: str
    registros: List[FrequenciaItem]


class NotaPayload(BaseModel):
    turma_id: int
    aluno_id: int
    nota1: float
    nota2: float


class CalendarioPayload(BaseModel):
    turma_id: int
    titulo: str
    tipo: str
    data: str
    descricao: Optional[str] = ""


class StatusAtestadoPayload(BaseModel):
    status: str


class RequerimentoPayload(BaseModel):
    tipo: str
    justificativa: str


class ResponderRequerimentoPayload(BaseModel):
    status: str
    parecer: Optional[str] = ""


class AvisoAdminPayload(BaseModel):
    titulo: str
    conteudo: str


class AvisoTurmaPayload(BaseModel):
    turma_id: int
    titulo: str
    conteudo: str


class ChatRequest(BaseModel):
    message: str


def salvar_upload(file: UploadFile, pasta: str) -> tuple:
    original = os.path.basename(file.filename or "arquivo")
    limpo = re.sub(r"[^A-Za-z0-9._-]", "_", original)[-80:] or "arquivo"
    nome = f"{secrets.token_hex(8)}_{limpo}"
    destino = os.path.join("uploads", pasta, nome)
    total = 0
    excedeu = False
    with open(destino, "wb") as buffer:
        while True:
            bloco = file.file.read(1024 * 1024)
            if not bloco:
                break
            total += len(bloco)
            if total > MAX_UPLOAD_BYTES:
                excedeu = True
                break
            buffer.write(bloco)
    if excedeu:
        os.remove(destino)
        raise HTTPException(status_code=413, detail="Arquivo excede o limite de 10 MB")
    return original, f"/uploads/{pasta}/{nome}"


def validar_data(valor: str, mensagem: str = "Data inválida") -> str:
    try:
        datetime.strptime(valor, "%Y-%m-%d")
    except Exception:
        raise HTTPException(status_code=400, detail=mensagem)
    return valor


def validar_senha_nova(senha: str, confirmacao: str) -> None:
    if len(senha) < 6:
        raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 6 caracteres")
    if senha != confirmacao:
        raise HTTPException(status_code=400, detail="A confirmação de senha não confere")


def info_usuario(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "nome": user.nome,
        "email": user.email,
        "role": user.role,
        "curso": user.curso,
        "campus": user.campus,
        "primeiro_acesso": bool(user.primeiro_acesso)
    }


def calcular_boletim(aluno: User, db: Session) -> dict:
    matriculas = db.query(MatriculaTurma).filter(MatriculaTurma.aluno_id == aluno.id).all()
    turma_ids = [m.turma_id for m in matriculas]
    turmas = db.query(Turma).filter(Turma.id.in_(turma_ids)).all() if turma_ids else []
    turma_map = {t.id: t for t in turmas}
    profs_map = {u.id: u.nome for u in db.query(User).filter(User.role == "professor").all()}

    disciplinas = []
    soma_medias = 0.0
    total_aulas = 0
    total_presencas = 0

    for m in matriculas:
        t = turma_map.get(m.turma_id)
        if not t:
            continue
        media = round((m.nota1 + m.nota2) / 2.0, 2)
        soma_medias += media
        freqs = db.query(Frequencia).filter(Frequencia.turma_id == t.id, Frequencia.aluno_id == aluno.id).all()
        aulas_t = len(freqs)
        pres_t = sum(1 for f in freqs if f.presente)
        total_aulas += aulas_t
        total_presencas += pres_t
        pct = round((pres_t / aulas_t) * 100, 1) if aulas_t > 0 else 100.0
        disciplinas.append({
            "turma_id": t.id,
            "codigo": t.codigo,
            "nome": t.nome,
            "professor": profs_map.get(t.professor_id, "---"),
            "carga_horaria": t.carga_horaria,
            "nota1": m.nota1,
            "nota2": m.nota2,
            "media": media,
            "frequencia": pct,
            "aulas_registradas": aulas_t,
            "faltas": aulas_t - pres_t,
            "status": m.status
        })

    ira = round(soma_medias / len(disciplinas), 2) if disciplinas else 0.0
    freq_geral = round((total_presencas / total_aulas) * 100, 1) if total_aulas > 0 else 100.0
    return {
        "disciplinas": disciplinas,
        "ira": ira,
        "frequencia_geral": freq_geral,
        "turma_ids": turma_ids,
        "turma_map": turma_map,
        "total_faltas": total_aulas - total_presencas
    }


def serializar_aviso(a: Aviso, autores: dict, turma_map: dict) -> dict:
    turma = turma_map.get(a.turma_id) if a.turma_id else None
    return {
        "id": a.id,
        "titulo": a.titulo,
        "conteudo": a.conteudo,
        "criado_em": a.criado_em,
        "autor": autores.get(a.autor_id, "---"),
        "turma_nome": f"{turma.codigo} - {turma.nome}" if turma else "Institucional"
    }


def dados_admin(user: User, db: Session) -> dict:
    users = db.query(User).order_by(User.id.asc()).all()
    turmas = db.query(Turma).order_by(Turma.id.asc()).all()
    horarios = db.query(Horario).all()
    atestados = db.query(Atestado).order_by(Atestado.id.desc()).all()
    requerimentos = db.query(Requerimento).order_by(Requerimento.id.desc()).all()
    avisos = db.query(Aviso).order_by(Aviso.id.desc()).all()
    auditoria = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    matriculas = db.query(MatriculaTurma).all()
    user_map = {u.id: u for u in users}
    turma_map = {t.id: t for t in turmas}
    autores = {u.id: u.nome for u in users}

    alunos_por_turma = {}
    for m in matriculas:
        al = user_map.get(m.aluno_id)
        if al:
            alunos_por_turma.setdefault(m.turma_id, []).append({
                "aluno_id": al.id,
                "matricula": al.username,
                "nome": al.nome
            })

    alunos = [u for u in users if u.role == "aluno"]
    professores = [u for u in users if u.role == "professor"]

    return {
        "user": info_usuario(user),
        "estatisticas": {
            "alunos": len(alunos),
            "professores": len(professores),
            "turmas": len(turmas),
            "atestados_pendentes": sum(1 for a in atestados if a.status == "Pendente"),
            "requerimentos_em_analise": sum(1 for r in requerimentos if r.status == "Em Análise")
        },
        "usuarios": [
            {
                "id": u.id,
                "username": u.username,
                "nome": u.nome,
                "email": u.email,
                "role": u.role,
                "curso": u.curso,
                "campus": u.campus,
                "codigo_ativacao": u.codigo_ativacao,
                "primeiro_acesso": bool(u.primeiro_acesso)
            }
            for u in users
        ],
        "alunos": [{"id": u.id, "username": u.username, "nome": u.nome, "curso": u.curso, "campus": u.campus} for u in alunos],
        "professores": [{"id": u.id, "username": u.username, "nome": u.nome, "curso": u.curso} for u in professores],
        "turmas": [
            {
                "id": t.id,
                "codigo": t.codigo,
                "nome": t.nome,
                "carga_horaria": t.carga_horaria,
                "periodo": t.periodo,
                "professor_id": t.professor_id,
                "professor_nome": user_map[t.professor_id].nome if t.professor_id in user_map else "---",
                "total_alunos": len(alunos_por_turma.get(t.id, [])),
                "alunos": alunos_por_turma.get(t.id, [])
            }
            for t in turmas
        ],
        "horarios": [
            {
                "id": h.id,
                "turma_id": h.turma_id,
                "turma_nome": f"{turma_map[h.turma_id].codigo} - {turma_map[h.turma_id].nome}" if h.turma_id in turma_map else "---",
                "dia_semana": h.dia_semana,
                "hora_inicio": h.hora_inicio,
                "hora_fim": h.hora_fim,
                "sala": h.sala
            }
            for h in horarios
        ],
        "atestados": [
            {
                "id": a.id,
                "aluno_nome": user_map[a.aluno_id].nome if a.aluno_id in user_map else "---",
                "aluno_matricula": user_map[a.aluno_id].username if a.aluno_id in user_map else "---",
                "data_inicio": a.data_inicio,
                "dias": a.dias,
                "motivo": a.motivo,
                "arquivo_nome": a.arquivo_nome,
                "arquivo_caminho": a.arquivo_caminho,
                "status": a.status
            }
            for a in atestados
        ],
        "requerimentos": [
            {
                "id": r.id,
                "aluno_nome": user_map[r.aluno_id].nome if r.aluno_id in user_map else "---",
                "aluno_matricula": user_map[r.aluno_id].username if r.aluno_id in user_map else "---",
                "tipo": r.tipo,
                "justificativa": r.justificativa,
                "status": r.status,
                "parecer": r.parecer,
                "criado_em": r.criado_em
            }
            for r in requerimentos
        ],
        "avisos": [serializar_aviso(a, autores, turma_map) for a in avisos],
        "auditoria": [
            {"id": l.id, "ator": l.ator, "acao": l.acao, "detalhes": l.detalhes, "data_hora": l.data_hora}
            for l in auditoria
        ]
    }


def dados_professor(user: User, db: Session) -> dict:
    turmas = db.query(Turma).filter(Turma.professor_id == user.id).order_by(Turma.id.asc()).all()
    turma_ids = [t.id for t in turmas]
    turma_map = {t.id: t for t in turmas}
    atividades = db.query(Atividade).filter(Atividade.turma_id.in_(turma_ids)).order_by(Atividade.id.desc()).all() if turma_ids else []
    ativ_map = {a.id: a for a in atividades}
    entregas = db.query(EntregaAtividade).filter(EntregaAtividade.atividade_id.in_(list(ativ_map.keys()))).order_by(EntregaAtividade.id.desc()).all() if ativ_map else []
    alunos_map = {u.id: u for u in db.query(User).filter(User.role == "aluno").all()}
    autores = {u.id: u.nome for u in db.query(User).all()}

    filtro_eventos = EventoCalendario.turma_id.is_(None)
    if turma_ids:
        filtro_eventos = or_(EventoCalendario.turma_id.is_(None), EventoCalendario.turma_id.in_(turma_ids))
    eventos = db.query(EventoCalendario).filter(filtro_eventos).order_by(EventoCalendario.data.asc()).all()

    filtro_avisos = Aviso.turma_id.is_(None)
    if turma_ids:
        filtro_avisos = or_(Aviso.turma_id.is_(None), Aviso.turma_id.in_(turma_ids))
    avisos = db.query(Aviso).filter(filtro_avisos).order_by(Aviso.id.desc()).all()

    return {
        "user": info_usuario(user),
        "turmas": [
            {"id": t.id, "codigo": t.codigo, "nome": t.nome, "periodo": t.periodo, "carga_horaria": t.carga_horaria}
            for t in turmas
        ],
        "atividades": [
            {
                "id": a.id,
                "turma_id": a.turma_id,
                "turma_nome": f"{turma_map[a.turma_id].codigo} - {turma_map[a.turma_id].nome}",
                "titulo": a.titulo,
                "descricao": a.descricao,
                "tipo": a.tipo,
                "data_entrega": a.data_entrega,
                "arquivo_nome": a.arquivo_nome,
                "arquivo_caminho": a.arquivo_caminho,
                "criado_em": a.criado_em
            }
            for a in atividades
        ],
        "entregas": [
            {
                "id": e.id,
                "atividade_titulo": ativ_map[e.atividade_id].titulo,
                "aluno_nome": alunos_map[e.aluno_id].nome if e.aluno_id in alunos_map else "---",
                "aluno_matricula": alunos_map[e.aluno_id].username if e.aluno_id in alunos_map else "---",
                "comentario": e.comentario,
                "arquivo_nome": e.arquivo_nome,
                "arquivo_caminho": e.arquivo_caminho,
                "enviado_em": e.enviado_em
            }
            for e in entregas
        ],
        "eventos": [
            {
                "id": ev.id,
                "titulo": ev.titulo,
                "tipo": ev.tipo,
                "data": ev.data,
                "descricao": ev.descricao,
                "turma_nome": turma_map[ev.turma_id].nome if ev.turma_id in turma_map else "Institucional"
            }
            for ev in eventos
        ],
        "avisos": [serializar_aviso(a, autores, turma_map) for a in avisos]
    }


def dados_aluno(user: User, db: Session) -> dict:
    boletim = calcular_boletim(user, db)
    turma_ids = boletim["turma_ids"]
    turma_map = boletim["turma_map"]

    horarios = db.query(Horario).filter(Horario.turma_id.in_(turma_ids)).all() if turma_ids else []
    atividades = db.query(Atividade).filter(Atividade.turma_id.in_(turma_ids)).order_by(Atividade.id.desc()).all() if turma_ids else []
    minhas_entregas = {e.atividade_id: e for e in db.query(EntregaAtividade).filter(EntregaAtividade.aluno_id == user.id).all()}
    eventos = db.query(EventoCalendario).order_by(EventoCalendario.data.asc()).all()
    atestados = db.query(Atestado).filter(Atestado.aluno_id == user.id).order_by(Atestado.id.desc()).all()
    requerimentos = db.query(Requerimento).filter(Requerimento.aluno_id == user.id).order_by(Requerimento.id.desc()).all()
    autores = {u.id: u.nome for u in db.query(User).all()}

    filtro_avisos = Aviso.turma_id.is_(None)
    if turma_ids:
        filtro_avisos = or_(Aviso.turma_id.is_(None), Aviso.turma_id.in_(turma_ids))
    avisos = db.query(Aviso).filter(filtro_avisos).order_by(Aviso.id.desc()).all()

    return {
        "user": info_usuario(user),
        "ira": boletim["ira"],
        "frequencia_geral": boletim["frequencia_geral"],
        "disciplinas": boletim["disciplinas"],
        "horarios": [
            {
                "dia_semana": h.dia_semana,
                "hora_inicio": h.hora_inicio,
                "hora_fim": h.hora_fim,
                "sala": h.sala,
                "disciplina": turma_map[h.turma_id].nome if h.turma_id in turma_map else "---"
            }
            for h in horarios
        ],
        "atividades": [
            {
                "id": a.id,
                "turma_id": a.turma_id,
                "turma_nome": f"{turma_map[a.turma_id].codigo} - {turma_map[a.turma_id].nome}",
                "titulo": a.titulo,
                "descricao": a.descricao,
                "tipo": a.tipo,
                "data_entrega": a.data_entrega,
                "arquivo_nome": a.arquivo_nome,
                "arquivo_caminho": a.arquivo_caminho,
                "entregue": a.id in minhas_entregas,
                "entrega_info": minhas_entregas[a.id].enviado_em if a.id in minhas_entregas else ""
            }
            for a in atividades
        ],
        "eventos": [
            {
                "id": ev.id,
                "titulo": ev.titulo,
                "tipo": ev.tipo,
                "data": ev.data,
                "descricao": ev.descricao,
                "turma_nome": turma_map[ev.turma_id].nome if ev.turma_id in turma_map else "Institucional"
            }
            for ev in eventos if ev.turma_id is None or ev.turma_id in turma_ids
        ],
        "atestados": [
            {
                "id": at.id,
                "data_inicio": at.data_inicio,
                "dias": at.dias,
                "motivo": at.motivo,
                "arquivo_nome": at.arquivo_nome,
                "arquivo_caminho": at.arquivo_caminho,
                "status": at.status
            }
            for at in atestados
        ],
        "requerimentos": [
            {
                "id": r.id,
                "tipo": r.tipo,
                "justificativa": r.justificativa,
                "status": r.status,
                "parecer": r.parecer,
                "criado_em": r.criado_em
            }
            for r in requerimentos
        ],
        "tipos_requerimento": list(TIPOS_REQUERIMENTO),
        "avisos": [serializar_aviso(a, autores, turma_map) for a in avisos]
    }


def montar_declaracao(aluno: User, db: Session) -> dict:
    matriculas = db.query(MatriculaTurma).filter(MatriculaTurma.aluno_id == aluno.id).all()
    turma_ids = [m.turma_id for m in matriculas]
    turmas = db.query(Turma).filter(Turma.id.in_(turma_ids)).all() if turma_ids else []
    return {
        "nome": aluno.nome,
        "matricula": aluno.username,
        "curso": aluno.curso,
        "campus": aluno.campus,
        "data_emissao": agora("%d/%m/%Y às %H:%M"),
        "codigo_verificacao": f"SALTTO-{aluno.username}-{secrets.token_hex(3).upper()}",
        "disciplinas": [f"{t.codigo} - {t.nome} ({t.carga_horaria}h)" for t in turmas]
    }


def remover_turma(turma: Turma, db: Session) -> None:
    ativ_ids = [a.id for a in db.query(Atividade).filter(Atividade.turma_id == turma.id).all()]
    if ativ_ids:
        db.query(EntregaAtividade).filter(EntregaAtividade.atividade_id.in_(ativ_ids)).delete(synchronize_session=False)
    db.query(Atividade).filter(Atividade.turma_id == turma.id).delete(synchronize_session=False)
    db.query(MatriculaTurma).filter(MatriculaTurma.turma_id == turma.id).delete(synchronize_session=False)
    db.query(Horario).filter(Horario.turma_id == turma.id).delete(synchronize_session=False)
    db.query(Frequencia).filter(Frequencia.turma_id == turma.id).delete(synchronize_session=False)
    db.query(EventoCalendario).filter(EventoCalendario.turma_id == turma.id).delete(synchronize_session=False)
    db.query(Aviso).filter(Aviso.turma_id == turma.id).delete(synchronize_session=False)
    db.delete(turma)


@app.post("/api/login")
def login(payload: LoginPayload, response: Response, db: Session = Depends(get_db)):
    username = normalizar_username(payload.username)
    user = db.query(User).filter(User.username == username, User.ativo == True).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Matrícula/ID ou senha incorretos")
    definir_cookie(response, user)
    return info_usuario(user)


@app.post("/api/primeiro-acesso")
def primeiro_acesso(payload: PrimeiroAcessoPayload, response: Response, db: Session = Depends(get_db)):
    username = normalizar_username(payload.username)
    codigo = (payload.codigo_ativacao or "").strip().upper()
    user = db.query(User).filter(User.username == username, User.ativo == True).first()
    if not user or not hmac.compare_digest(user.codigo_ativacao or "", codigo):
        raise HTTPException(status_code=400, detail="Matrícula/ID ou código de ativação inválidos")
    if not user.primeiro_acesso:
        raise HTTPException(status_code=400, detail="Esta conta já foi ativada. Use o login normal")
    validar_senha_nova(payload.password, payload.confirmar_password)
    user.password_hash = hash_password(payload.password)
    user.primeiro_acesso = False
    auditar(db, user.username, "Primeiro acesso", f"Conta {user.username} ativada pelo próprio usuário")
    db.commit()
    definir_cookie(response, user)
    return info_usuario(user)


@app.post("/api/alterar-senha")
def alterar_senha(payload: AlterarSenhaPayload, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.senha_atual, user.password_hash):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")
    validar_senha_nova(payload.nova_senha, payload.confirmar_senha)
    user.password_hash = hash_password(payload.nova_senha)
    user.primeiro_acesso = False
    auditar(db, user.username, "Alteração de senha", f"Usuário {user.username} alterou a própria senha")
    db.commit()
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("saltto_session")
    return {"ok": True}


@app.get("/api/me")
def get_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role == "admin":
        return dados_admin(user, db)
    if user.role == "professor":
        return dados_professor(user, db)
    return dados_aluno(user, db)


@app.post("/api/admin/users")
def admin_create_user(payload: CreateUserPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    role = (payload.role or "").strip()
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Perfil inválido")
    nome = (payload.nome or "").strip()
    if not nome:
        raise HTTPException(status_code=400, detail="Informe o nome completo")

    username = normalizar_username(payload.username or "")
    if username:
        if not PADROES_ID[role].match(username):
            raise HTTPException(status_code=400, detail=f"ID fora do padrão. Formato esperado: {FORMATO_ID[role]}")
    else:
        username = gerar_id(role, db)
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Matrícula ou ID já cadastrado")

    senha = (payload.password or "").strip()
    senha_provisoria = None
    if senha:
        if len(senha) < 6:
            raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 6 caracteres")
        primeiro = False
    else:
        senha = secrets.token_urlsafe(8)
        senha_provisoria = senha
        primeiro = True

    curso_padrao = {
        "aluno": "Técnico Integrado em Informática / IA",
        "professor": "Departamento Acadêmico",
        "admin": "Administração Institucional"
    }[role]

    novo = User(
        username=username,
        nome=nome,
        email=(payload.email or "").strip(),
        role=role,
        curso=(payload.curso or "").strip() or curso_padrao,
        campus=(payload.campus or "").strip() or "Campus Teresina Central",
        password_hash=hash_password(senha),
        codigo_ativacao=gerar_codigo_ativacao(),
        primeiro_acesso=primeiro
    )
    db.add(novo)
    auditar(db, ator.username, "Cadastro de usuário", f"Criado {role} {username} - {nome}")
    db.commit()
    db.refresh(novo)
    return {
        "id": novo.id,
        "username": novo.username,
        "nome": novo.nome,
        "role": novo.role,
        "codigo_ativacao": novo.codigo_ativacao,
        "primeiro_acesso": novo.primeiro_acesso,
        "senha_provisoria": senha_provisoria
    }


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    alvo = db.query(User).filter(User.id == user_id).first()
    if not alvo:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if alvo.id == ator.id:
        raise HTTPException(status_code=400, detail="Você não pode excluir a própria conta")
    if alvo.role == "admin" and db.query(User).filter(User.role == "admin").count() <= 1:
        raise HTTPException(status_code=400, detail="Não é possível excluir o último administrador")
    if alvo.role == "professor" and db.query(Turma).filter(Turma.professor_id == alvo.id).count() > 0:
        raise HTTPException(status_code=400, detail="Professor vinculado a turmas. Exclua ou reatribua as turmas antes")
    if alvo.role == "aluno":
        db.query(MatriculaTurma).filter(MatriculaTurma.aluno_id == alvo.id).delete(synchronize_session=False)
        db.query(Frequencia).filter(Frequencia.aluno_id == alvo.id).delete(synchronize_session=False)
        db.query(EntregaAtividade).filter(EntregaAtividade.aluno_id == alvo.id).delete(synchronize_session=False)
        db.query(Atestado).filter(Atestado.aluno_id == alvo.id).delete(synchronize_session=False)
        db.query(Requerimento).filter(Requerimento.aluno_id == alvo.id).delete(synchronize_session=False)
    db.query(Aviso).filter(Aviso.autor_id == alvo.id).delete(synchronize_session=False)
    auditar(db, ator.username, "Exclusão de usuário", f"Removido {alvo.role} {alvo.username} - {alvo.nome}")
    db.delete(alvo)
    db.commit()
    return {"ok": True}


@app.post("/api/admin/turmas")
def admin_create_turma(payload: CreateTurmaPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    codigo = payload.codigo.strip().upper()
    nome = payload.nome.strip()
    if not codigo or not nome:
        raise HTTPException(status_code=400, detail="Informe código e nome da turma")
    if payload.carga_horaria <= 0:
        raise HTTPException(status_code=400, detail="Carga horária inválida")
    if db.query(Turma).filter(Turma.codigo == codigo).first():
        raise HTTPException(status_code=400, detail="Código de turma já cadastrado")
    prof = db.query(User).filter(User.id == payload.professor_id, User.role == "professor").first()
    if not prof:
        raise HTTPException(status_code=400, detail="Professor inválido")
    db.add(Turma(
        codigo=codigo,
        nome=nome,
        carga_horaria=payload.carga_horaria,
        periodo=payload.periodo.strip() or "2026.2",
        professor_id=prof.id
    ))
    auditar(db, ator.username, "Criação de turma", f"Turma {codigo} - {nome} (professor {prof.username})")
    db.commit()
    return {"ok": True}


@app.delete("/api/admin/turmas/{turma_id}")
def admin_delete_turma(turma_id: int, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == turma_id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    auditar(db, ator.username, "Exclusão de turma", f"Turma {turma.codigo} - {turma.nome} removida com seus vínculos")
    remover_turma(turma, db)
    db.commit()
    return {"ok": True}


@app.post("/api/admin/matricular-turma")
def admin_matricular_turma(payload: MatricularTurmaPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    aluno = db.query(User).filter(User.id == payload.aluno_id, User.role == "aluno").first()
    turma = db.query(Turma).filter(Turma.id == payload.turma_id).first()
    if not aluno or not turma:
        raise HTTPException(status_code=404, detail="Aluno ou turma não encontrado")
    exists = db.query(MatriculaTurma).filter(
        MatriculaTurma.aluno_id == aluno.id,
        MatriculaTurma.turma_id == turma.id
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="Aluno já matriculado nesta turma")
    db.add(MatriculaTurma(aluno_id=aluno.id, turma_id=turma.id))
    auditar(db, ator.username, "Enturmação", f"Aluno {aluno.username} matriculado na turma {turma.codigo}")
    db.commit()
    return {"ok": True}


@app.post("/api/admin/horarios")
def admin_create_horario(payload: HorarioPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == payload.turma_id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    if payload.dia_semana not in DIAS_SEMANA:
        raise HTTPException(status_code=400, detail="Dia da semana inválido")
    if not REGEX_HORA.match(payload.hora_inicio) or not REGEX_HORA.match(payload.hora_fim):
        raise HTTPException(status_code=400, detail="Horário inválido")
    if payload.hora_inicio >= payload.hora_fim:
        raise HTTPException(status_code=400, detail="O horário de início deve ser anterior ao de fim")
    sala = payload.sala.strip()
    if not sala:
        raise HTTPException(status_code=400, detail="Informe a sala ou laboratório")
    db.add(Horario(
        turma_id=turma.id,
        dia_semana=payload.dia_semana,
        hora_inicio=payload.hora_inicio,
        hora_fim=payload.hora_fim,
        sala=sala
    ))
    auditar(db, ator.username, "Criação de horário", f"{turma.codigo}: {payload.dia_semana} {payload.hora_inicio}-{payload.hora_fim} em {sala}")
    db.commit()
    return {"ok": True}


@app.delete("/api/admin/horarios/{horario_id}")
def admin_delete_horario(horario_id: int, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    horario = db.query(Horario).filter(Horario.id == horario_id).first()
    if not horario:
        raise HTTPException(status_code=404, detail="Horário não encontrado")
    auditar(db, ator.username, "Exclusão de horário", f"Horário {horario.dia_semana} {horario.hora_inicio}-{horario.hora_fim} ({horario.sala}) removido")
    db.delete(horario)
    db.commit()
    return {"ok": True}


@app.post("/api/admin/atestados/{atestado_id}/status")
def admin_update_atestado(atestado_id: int, payload: StatusAtestadoPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if payload.status not in STATUS_ATESTADO:
        raise HTTPException(status_code=400, detail="Status inválido")
    at = db.query(Atestado).filter(Atestado.id == atestado_id).first()
    if not at:
        raise HTTPException(status_code=404, detail="Atestado não encontrado")
    at.status = payload.status
    auditar(db, ator.username, "Avaliação de atestado", f"Atestado #{at.id} marcado como {payload.status}")
    db.commit()
    return {"ok": True}


@app.post("/api/admin/requerimentos/{requerimento_id}/responder")
def admin_responder_requerimento(requerimento_id: int, payload: ResponderRequerimentoPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if payload.status not in STATUS_REQUERIMENTO:
        raise HTTPException(status_code=400, detail="Status inválido")
    req = db.query(Requerimento).filter(Requerimento.id == requerimento_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requerimento não encontrado")
    req.status = payload.status
    req.parecer = (payload.parecer or "").strip()
    auditar(db, ator.username, "Resposta de requerimento", f"Requerimento #{req.id} ({req.tipo}) marcado como {payload.status}")
    db.commit()
    return {"ok": True}


@app.post("/api/admin/avisos")
def admin_criar_aviso(payload: AvisoAdminPayload, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    titulo = payload.titulo.strip()
    conteudo = payload.conteudo.strip()
    if not titulo or not conteudo:
        raise HTTPException(status_code=400, detail="Informe título e conteúdo do aviso")
    db.add(Aviso(autor_id=ator.id, turma_id=None, titulo=titulo, conteudo=conteudo, criado_em=agora()))
    auditar(db, ator.username, "Aviso institucional", f"Publicado: {titulo}")
    db.commit()
    return {"ok": True}


@app.get("/api/admin/declaracao/{aluno_id}")
def admin_declaracao(aluno_id: int, ator: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    aluno = db.query(User).filter(User.id == aluno_id, User.role == "aluno").first()
    if not aluno:
        raise HTTPException(status_code=404, detail="Aluno não encontrado")
    declaracao = montar_declaracao(aluno, db)
    auditar(db, ator.username, "Emissão de declaração", f"Declaração {declaracao['codigo_verificacao']} emitida para {aluno.username}")
    db.commit()
    return declaracao


@app.get("/api/aluno/declaracao")
def aluno_declaracao(user: User = Depends(require_role("aluno")), db: Session = Depends(get_db)):
    declaracao = montar_declaracao(user, db)
    auditar(db, user.username, "Emissão de declaração", f"Declaração {declaracao['codigo_verificacao']} emitida pelo próprio aluno")
    db.commit()
    return declaracao


@app.get("/api/professor/turma/{turma_id}/alunos")
def prof_get_alunos_turma(turma_id: int, user: User = Depends(require_role("professor")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    mats = db.query(MatriculaTurma).filter(MatriculaTurma.turma_id == turma.id).all()
    result = []
    for m in mats:
        al = db.query(User).filter(User.id == m.aluno_id).first()
        if al:
            result.append({
                "aluno_id": al.id,
                "matricula": al.username,
                "nome": al.nome,
                "nota1": m.nota1,
                "nota2": m.nota2
            })
    return result


@app.post("/api/professor/frequencia")
def prof_registrar_frequencia(payload: FrequenciaBatchPayload, user: User = Depends(require_role("professor")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == payload.turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    validar_data(payload.data, "Data da chamada inválida")
    matriculados = {m.aluno_id for m in db.query(MatriculaTurma).filter(MatriculaTurma.turma_id == turma.id).all()}
    for item in payload.registros:
        if item.aluno_id not in matriculados:
            continue
        existente = db.query(Frequencia).filter(
            Frequencia.turma_id == turma.id,
            Frequencia.aluno_id == item.aluno_id,
            Frequencia.data == payload.data
        ).first()
        if existente:
            existente.presente = item.presente
        else:
            db.add(Frequencia(turma_id=turma.id, aluno_id=item.aluno_id, data=payload.data, presente=item.presente))
    auditar(db, user.username, "Chamada", f"Frequência de {turma.codigo} em {payload.data} registrada")
    db.commit()
    return {"ok": True}


@app.post("/api/professor/notas")
def prof_lancar_notas(payload: NotaPayload, user: User = Depends(require_role("professor")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == payload.turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    if not (0 <= payload.nota1 <= 10) or not (0 <= payload.nota2 <= 10):
        raise HTTPException(status_code=400, detail="As notas devem estar entre 0 e 10")
    mat = db.query(MatriculaTurma).filter(MatriculaTurma.turma_id == turma.id, MatriculaTurma.aluno_id == payload.aluno_id).first()
    if not mat:
        raise HTTPException(status_code=404, detail="Matrícula não encontrada")
    mat.nota1 = payload.nota1
    mat.nota2 = payload.nota2
    media = (payload.nota1 + payload.nota2) / 2.0
    mat.status = "Aprovado" if media >= 7.0 else "Cursando"
    auditar(db, user.username, "Lançamento de notas", f"{turma.codigo}: aluno #{payload.aluno_id} N1={payload.nota1} N2={payload.nota2}")
    db.commit()
    return {"ok": True}


@app.post("/api/professor/atividades")
async def prof_criar_atividade(
    turma_id: int = Form(...),
    titulo: str = Form(...),
    descricao: str = Form(""),
    tipo: str = Form("Atividade"),
    data_entrega: str = Form(""),
    arquivo: Optional[UploadFile] = File(None),
    user: User = Depends(require_role("professor")),
    db: Session = Depends(get_db)
):
    turma = db.query(Turma).filter(Turma.id == turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    if tipo not in TIPOS_ATIVIDADE:
        raise HTTPException(status_code=400, detail="Tipo de publicação inválido")
    titulo = titulo.strip()
    if not titulo:
        raise HTTPException(status_code=400, detail="Informe o título")
    data_entrega = data_entrega.strip()
    if data_entrega:
        validar_data(data_entrega, "Data de entrega inválida")
    arq_nome, arq_path = "", ""
    if arquivo and arquivo.filename:
        arq_nome, arq_path = salvar_upload(arquivo, "atividades")
    ativ = Atividade(
        turma_id=turma.id,
        titulo=titulo,
        descricao=descricao.strip(),
        tipo=tipo,
        data_entrega=data_entrega,
        arquivo_nome=arq_nome,
        arquivo_caminho=arq_path,
        criado_em=agora("%Y-%m-%d")
    )
    db.add(ativ)
    if data_entrega:
        db.add(EventoCalendario(
            turma_id=turma.id,
            titulo=f"{tipo}: {titulo}",
            tipo="Atividade",
            data=data_entrega,
            descricao=descricao.strip()
        ))
    auditar(db, user.username, "Publicação de atividade", f"{turma.codigo}: {tipo} '{titulo}'")
    db.commit()
    return {"ok": True}


@app.post("/api/professor/calendario")
def prof_criar_evento(payload: CalendarioPayload, user: User = Depends(require_role("professor")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == payload.turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    if payload.tipo not in TIPOS_EVENTO_PROFESSOR:
        raise HTTPException(status_code=400, detail="Tipo de evento inválido")
    titulo = payload.titulo.strip()
    if not titulo:
        raise HTTPException(status_code=400, detail="Informe o título do evento")
    validar_data(payload.data, "Data do evento inválida")
    db.add(EventoCalendario(
        turma_id=turma.id,
        titulo=titulo,
        tipo=payload.tipo,
        data=payload.data,
        descricao=(payload.descricao or "").strip()
    ))
    auditar(db, user.username, "Agendamento no calendário", f"{turma.codigo}: {payload.tipo} '{titulo}' em {payload.data}")
    db.commit()
    return {"ok": True}


@app.post("/api/professor/avisos")
def prof_criar_aviso(payload: AvisoTurmaPayload, user: User = Depends(require_role("professor")), db: Session = Depends(get_db)):
    turma = db.query(Turma).filter(Turma.id == payload.turma_id, Turma.professor_id == user.id).first()
    if not turma:
        raise HTTPException(status_code=404, detail="Turma não encontrada")
    titulo = payload.titulo.strip()
    conteudo = payload.conteudo.strip()
    if not titulo or not conteudo:
        raise HTTPException(status_code=400, detail="Informe título e conteúdo do aviso")
    db.add(Aviso(autor_id=user.id, turma_id=turma.id, titulo=titulo, conteudo=conteudo, criado_em=agora()))
    auditar(db, user.username, "Aviso de turma", f"{turma.codigo}: {titulo}")
    db.commit()
    return {"ok": True}


@app.post("/api/aluno/atividades/{atividade_id}/entregar")
async def aluno_entregar_atividade(
    atividade_id: int,
    comentario: str = Form(""),
    arquivo: Optional[UploadFile] = File(None),
    user: User = Depends(require_role("aluno")),
    db: Session = Depends(get_db)
):
    ativ = db.query(Atividade).filter(Atividade.id == atividade_id).first()
    if not ativ:
        raise HTTPException(status_code=404, detail="Atividade não encontrada")
    if ativ.tipo != "Atividade":
        raise HTTPException(status_code=400, detail="Este item é um material e não aceita entregas")
    matriculado = db.query(MatriculaTurma).filter(MatriculaTurma.aluno_id == user.id, MatriculaTurma.turma_id == ativ.turma_id).first()
    if not matriculado:
        raise HTTPException(status_code=403, detail="Você não está matriculado nesta turma")
    tem_arquivo = bool(arquivo and arquivo.filename)
    if not tem_arquivo and not comentario.strip():
        raise HTTPException(status_code=400, detail="Envie um arquivo ou escreva um comentário")
    arq_nome, arq_path = "", ""
    if tem_arquivo:
        arq_nome, arq_path = salvar_upload(arquivo, "entregas")
    existente = db.query(EntregaAtividade).filter(EntregaAtividade.atividade_id == ativ.id, EntregaAtividade.aluno_id == user.id).first()
    if existente:
        existente.comentario = comentario.strip()
        existente.arquivo_nome = arq_nome
        existente.arquivo_caminho = arq_path
        existente.enviado_em = agora()
    else:
        db.add(EntregaAtividade(
            atividade_id=ativ.id,
            aluno_id=user.id,
            comentario=comentario.strip(),
            arquivo_nome=arq_nome,
            arquivo_caminho=arq_path,
            enviado_em=agora()
        ))
    db.commit()
    return {"ok": True}


@app.post("/api/aluno/atestados")
async def aluno_enviar_atestado(
    data_inicio: str = Form(...),
    dias: int = Form(...),
    motivo: str = Form(...),
    arquivo: UploadFile = File(...),
    user: User = Depends(require_role("aluno")),
    db: Session = Depends(get_db)
):
    validar_data(data_inicio, "Data de início inválida")
    if dias < 1 or dias > 365:
        raise HTTPException(status_code=400, detail="Quantidade de dias inválida")
    if not motivo.strip():
        raise HTTPException(status_code=400, detail="Informe o motivo do afastamento")
    if not arquivo.filename:
        raise HTTPException(status_code=400, detail="Anexe o documento do atestado")
    arq_nome, arq_path = salvar_upload(arquivo, "atestados")
    db.add(Atestado(
        aluno_id=user.id,
        data_inicio=data_inicio,
        dias=dias,
        motivo=motivo.strip(),
        arquivo_nome=arq_nome,
        arquivo_caminho=arq_path,
        status="Pendente"
    ))
    db.commit()
    return {"ok": True}


@app.post("/api/aluno/requerimentos")
def aluno_criar_requerimento(payload: RequerimentoPayload, user: User = Depends(require_role("aluno")), db: Session = Depends(get_db)):
    if payload.tipo not in TIPOS_REQUERIMENTO:
        raise HTTPException(status_code=400, detail="Tipo de requerimento inválido")
    justificativa = payload.justificativa.strip()
    if not justificativa:
        raise HTTPException(status_code=400, detail="Informe a justificativa")
    db.add(Requerimento(
        aluno_id=user.id,
        tipo=payload.tipo,
        justificativa=justificativa,
        status="Em Análise",
        parecer="",
        criado_em=agora()
    ))
    db.commit()
    return {"ok": True}


@app.get("/uploads/{pasta}/{nome}")
def baixar_upload(pasta: str, nome: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if pasta not in PASTAS_UPLOAD:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    nome = os.path.basename(nome)
    caminho_fisico = os.path.join("uploads", pasta, nome)
    if not os.path.isfile(caminho_fisico):
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    caminho_url = f"/uploads/{pasta}/{nome}"
    permitido = user.role == "admin"

    if pasta == "atestados":
        at = db.query(Atestado).filter(Atestado.arquivo_caminho == caminho_url).first()
        permitido = permitido or bool(at and at.aluno_id == user.id)
    elif pasta == "entregas":
        ent = db.query(EntregaAtividade).filter(EntregaAtividade.arquivo_caminho == caminho_url).first()
        if ent:
            if ent.aluno_id == user.id:
                permitido = True
            elif user.role == "professor":
                ativ = db.query(Atividade).filter(Atividade.id == ent.atividade_id).first()
                turma = db.query(Turma).filter(Turma.id == ativ.turma_id).first() if ativ else None
                permitido = bool(turma and turma.professor_id == user.id)
    else:
        ativ = db.query(Atividade).filter(Atividade.arquivo_caminho == caminho_url).first()
        if ativ:
            if user.role == "professor":
                turma = db.query(Turma).filter(Turma.id == ativ.turma_id).first()
                permitido = bool(turma and turma.professor_id == user.id)
            elif user.role == "aluno":
                permitido = db.query(MatriculaTurma).filter(
                    MatriculaTurma.aluno_id == user.id,
                    MatriculaTurma.turma_id == ativ.turma_id
                ).first() is not None

    if not permitido:
        raise HTTPException(status_code=403, detail="Acesso negado a este arquivo")
    nome_original = nome.split("_", 1)[1] if "_" in nome else nome
    return FileResponse(caminho_fisico, filename=nome_original)


def contem(msg: str, chaves: list) -> bool:
    return any(k in msg for k in chaves)


@app.post("/api/chat")
def chatbot_endpoint(payload: ChatRequest, request: Request, db: Session = Depends(get_db)):
    msg = payload.message.lower().strip()
    token = request.cookies.get("saltto_session")
    user = None
    if token:
        data = decode_session_token(token)
        if data:
            user = db.query(User).filter(User.id == data["user_id"], User.ativo == True).first()

    if user and user.role == "aluno":
        if contem(msg, ["nota", "ira", "média", "media", "boletim"]):
            b = calcular_boletim(user, db)
            if not b["disciplinas"]:
                return {"reply": f"{user.nome}, você ainda não está matriculado em nenhuma turma."}
            linhas = "; ".join(f"{d['codigo']}: N1 {d['nota1']:.1f}, N2 {d['nota2']:.1f}, média {d['media']:.2f} ({d['status']})" for d in b["disciplinas"])
            return {"reply": f"Seu IRA atual é {b['ira']:.2f}. Detalhes: {linhas}."}
        if contem(msg, ["frequência", "frequencia", "falta", "presença", "presenca"]):
            b = calcular_boletim(user, db)
            return {"reply": f"Sua frequência global é {b['frequencia_geral']}% com {b['total_faltas']} falta(s) registrada(s). A frequência mínima exigida é 75%."}
        if contem(msg, ["minhas turmas", "minhas disciplinas", "turmas", "disciplinas"]):
            b = calcular_boletim(user, db)
            if not b["disciplinas"]:
                return {"reply": "Você ainda não está matriculado em nenhuma turma."}
            nomes = "; ".join(f"{d['codigo']} - {d['nome']} (Prof. {d['professor']})" for d in b["disciplinas"])
            return {"reply": f"Você está matriculado em {len(b['disciplinas'])} turma(s): {nomes}."}
        if contem(msg, ["requerimento", "protocolo"]):
            reqs = db.query(Requerimento).filter(Requerimento.aluno_id == user.id).order_by(Requerimento.id.desc()).all()
            if not reqs:
                return {"reply": "Você não possui requerimentos abertos. Abra um na aba 'Requerimentos'."}
            linhas = "; ".join(f"#{r.id} {r.tipo}: {r.status}" + (f" (parecer: {r.parecer})" if r.parecer else "") for r in reqs)
            return {"reply": f"Seus requerimentos: {linhas}."}
        if contem(msg, ["meu atestado", "meus atestados", "status do atestado"]):
            ats = db.query(Atestado).filter(Atestado.aluno_id == user.id).order_by(Atestado.id.desc()).all()
            if not ats:
                return {"reply": "Você ainda não enviou atestados."}
            linhas = "; ".join(f"#{a.id} a partir de {a.data_inicio} ({a.dias} dia(s)): {a.status}" for a in ats)
            return {"reply": f"Seus atestados: {linhas}."}

    if user and user.role == "professor" and contem(msg, ["minhas turmas", "turmas"]):
        turmas = db.query(Turma).filter(Turma.professor_id == user.id).all()
        if not turmas:
            return {"reply": "Você ainda não possui turmas vinculadas."}
        partes = []
        for t in turmas:
            total = db.query(MatriculaTurma).filter(MatriculaTurma.turma_id == t.id).count()
            partes.append(f"{t.codigo} - {t.nome} ({total} aluno(s))")
        return {"reply": "Suas turmas: " + "; ".join(partes) + "."}

    if user and user.role == "admin" and contem(msg, ["pendente", "pendência", "pendencia"]):
        ats = db.query(Atestado).filter(Atestado.status == "Pendente").count()
        reqs = db.query(Requerimento).filter(Requerimento.status == "Em Análise").count()
        return {"reply": f"Pendências atuais: {ats} atestado(s) aguardando avaliação e {reqs} requerimento(s) em análise."}

    regras = [
        (["primeiro acesso", "ativação", "ativacao", "criar senha", "código de ativação", "codigo de ativacao"],
         "No Primeiro Acesso, abra a aba 'Primeiro Acesso (Criar Senha)' na tela de login, informe sua matrícula/ID, o código de ativação de 6 caracteres fornecido pela secretaria e crie sua senha."),
        (["alterar senha", "trocar senha", "mudar senha", "esqueci"],
         "Para trocar a senha, use 'Alterar Minha Senha' no menu lateral. Se esqueceu a senha, procure a secretaria para receber um novo código de ativação."),
        (["padrão", "padrao", "formato", "id institucional", "login", "matrícula", "matricula", "renovação", "renovacao"],
         "Os padrões de acesso são: alunos com matrícula de 8 dígitos (ex: 20261064), professores PROF-AAAA-XXXX (ex: PROF-2026-0001) e administradores ADM-AAAA-XXXX (ex: ADM-2026-0001). Novas matrículas e a renovação semestral são tratadas pelo Setor Administrativo."),
        (["atestado", "médico", "medico", "abono"],
         "Anexe seu atestado em PDF ou imagem na aba 'Atestados Médicos'. O status (Pendente, Deferido ou Indeferido) aparece na mesma tela."),
        (["prova", "calendário", "calendario", "exame"],
         "Datas de provas, entregas e eventos institucionais aparecem automaticamente na aba 'Calendário Acadêmico'."),
        (["declaração", "declaracao", "comprovante"],
         "A Declaração de Matrícula oficial, com código único de verificação, é emitida na aba de Secretaria/Declaração."),
        (["biblioteca", "livro"],
         "A biblioteca funciona de segunda a sexta das 07:30 às 21:00 e aos sábados das 08:00 às 13:00."),
        (["bolsa", "auxílio", "auxilio", "pibic"],
         "As bolsas institucionais exigem IRA mínimo de 7.0 e frequência igual ou superior a 75%."),
        (["restaurante", "almoço", "almoco", "jantar"],
         "O Restaurante Institucional serve almoço das 11:30 às 13:30 e jantar das 17:30 às 19:00."),
        (["requerimento", "protocolo", "segunda chamada", "trancamento", "carteira"],
         "Requerimentos digitais (Segunda Chamada, Revisão de Nota, Carteira Estudantil, Aproveitamento de Disciplina e Trancamento) são abertos na aba 'Requerimentos' do portal do aluno.")
    ]
    for chaves, resposta in regras:
        if contem(msg, chaves):
            return {"reply": resposta}
    return {"reply": "Sou o Assistente Saltto! Pergunte sobre notas, IRA, frequência, requerimentos, atestados, Primeiro Acesso, padrões de matrícula, declarações, biblioteca, bolsas ou restaurante."}


@app.get("/")
def read_root():
    return FileResponse("index.html")
