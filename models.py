from sqlalchemy import Column, Integer, String, Float, Boolean, Text, ForeignKey
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    nome = Column(String, nullable=False)
    email = Column(String, default="")
    role = Column(String, nullable=False)
    curso = Column(String, default="Técnico Integrado em Informática / IA")
    campus = Column(String, default="Campus Teresina Central")
    password_hash = Column(String, nullable=False)
    codigo_ativacao = Column(String, default="")
    primeiro_acesso = Column(Boolean, default=False)
    ativo = Column(Boolean, default=True)


class Turma(Base):
    __tablename__ = "turmas"
    id = Column(Integer, primary_key=True, index=True)
    codigo = Column(String, unique=True, nullable=False)
    nome = Column(String, nullable=False)
    carga_horaria = Column(Integer, default=60)
    periodo = Column(String, default="2026.2")
    professor_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class MatriculaTurma(Base):
    __tablename__ = "matriculas_turmas"
    id = Column(Integer, primary_key=True, index=True)
    aluno_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=False)
    nota1 = Column(Float, default=0.0)
    nota2 = Column(Float, default=0.0)
    status = Column(String, default="Cursando")


class Horario(Base):
    __tablename__ = "horarios"
    id = Column(Integer, primary_key=True, index=True)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=False)
    dia_semana = Column(String, nullable=False)
    hora_inicio = Column(String, nullable=False)
    hora_fim = Column(String, nullable=False)
    sala = Column(String, nullable=False)


class Frequencia(Base):
    __tablename__ = "frequencias"
    id = Column(Integer, primary_key=True, index=True)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=False)
    aluno_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    data = Column(String, nullable=False)
    presente = Column(Boolean, default=True)


class Atividade(Base):
    __tablename__ = "atividades"
    id = Column(Integer, primary_key=True, index=True)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=False)
    titulo = Column(String, nullable=False)
    descricao = Column(Text, default="")
    tipo = Column(String, default="Atividade")
    data_entrega = Column(String, default="")
    arquivo_nome = Column(String, default="")
    arquivo_caminho = Column(String, default="")
    criado_em = Column(String, nullable=False)


class EntregaAtividade(Base):
    __tablename__ = "entregas_atividades"
    id = Column(Integer, primary_key=True, index=True)
    atividade_id = Column(Integer, ForeignKey("atividades.id"), nullable=False)
    aluno_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    comentario = Column(Text, default="")
    arquivo_nome = Column(String, default="")
    arquivo_caminho = Column(String, default="")
    enviado_em = Column(String, nullable=False)


class Atestado(Base):
    __tablename__ = "atestados"
    id = Column(Integer, primary_key=True, index=True)
    aluno_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    data_inicio = Column(String, nullable=False)
    dias = Column(Integer, default=1)
    motivo = Column(Text, nullable=False)
    arquivo_nome = Column(String, default="")
    arquivo_caminho = Column(String, default="")
    status = Column(String, default="Pendente")


class Requerimento(Base):
    __tablename__ = "requerimentos"
    id = Column(Integer, primary_key=True, index=True)
    aluno_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    tipo = Column(String, nullable=False)
    justificativa = Column(Text, nullable=False)
    status = Column(String, default="Em Análise")
    parecer = Column(Text, default="")
    criado_em = Column(String, nullable=False)


class EventoCalendario(Base):
    __tablename__ = "eventos_calendario"
    id = Column(Integer, primary_key=True, index=True)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=True)
    titulo = Column(String, nullable=False)
    tipo = Column(String, default="Prova")
    data = Column(String, nullable=False)
    descricao = Column(Text, default="")


class Aviso(Base):
    __tablename__ = "avisos"
    id = Column(Integer, primary_key=True, index=True)
    autor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    turma_id = Column(Integer, ForeignKey("turmas.id"), nullable=True)
    titulo = Column(String, nullable=False)
    conteudo = Column(Text, nullable=False)
    criado_em = Column(String, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    ator = Column(String, nullable=False)
    acao = Column(String, nullable=False)
    detalhes = Column(Text, default="")
    data_hora = Column(String, nullable=False)
