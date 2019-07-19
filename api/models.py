# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from dataclasses import dataclass, asdict
from typing import List, Optional, TypeVar, Type
from data import models

from flask import url_for, request

T = TypeVar('T')


@dataclass()
class _BaseAPIModel:
    id: int

    def to_dict(self):
        d = asdict(self)
        # for k, v in d.copy().items():
        #     if v is None:
        #         d.pop(k)
        return d

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.id == other.id

    @classmethod
    def from_db(cls: Type[T], o, full=False) -> T:
        raise NotImplementedError


@dataclass()
class User(_BaseAPIModel):
    username: str
    points: int
    is_admin: bool
    first_name: str
    last_name: Optional[str] = None
    email: Optional[str] = None  # is not filled by `from_db` method
    is_confirmed: Optional[bool] = None
    solved_tasks: Optional[List['Task']] = None
    first_blood_tasks: Optional[List['Task']] = None
    author_of_tasks: Optional[List['Task']] = None

    @classmethod
    def from_db(cls, o: models.User, full=False) -> 'User':
        if full:
            is_confirmed = o.is_confirmed
            solved_tasks = [
                Task.from_db(s.task)
                for s in models.SolvedTask.query.filter_by(user_id=o.id).all()
            ]
            authored_tasks = [
                Task.from_db(t)
                for t in models.Task.query.filter_by(author_id=o.id).all()
            ]
            first_blood = []
            for t in solved_tasks:
                ts = models.SolvedTask.query.filter(models.SolvedTask.task_id == t.id).first()
                if ts.user_id == o.id:
                    first_blood.append(Task.from_db(ts.task))
        else:
            is_confirmed, solved_tasks, authored_tasks, first_blood = None, None, None, None
        return cls(
            id=o.id,
            username=o.username,
            points=o.points,
            is_admin=o.is_admin,
            is_confirmed=is_confirmed,
            first_name=o.first_name,
            last_name=o.last_name,
            solved_tasks=solved_tasks,
            first_blood_tasks=first_blood,
            author_of_tasks=authored_tasks
        )


@dataclass()
class File(_BaseAPIModel):
    task: 'Task'
    name: str
    url: str

    @classmethod
    def from_db(cls, o: models.TaskFile, full=False) -> 'File':
        root = request.url_root.rstrip('/')
        rel_url = url_for('static', filename=f'files/tasks/{o.task_id}/{o.file}')
        return cls(
            id=o.id,
            task=Task.from_db(o.task),
            name=o.file,
            url=root + rel_url
        )


@dataclass()
class Category(_BaseAPIModel):
    name: str
    tasks: Optional[List['Task']] = None
    articles: Optional[List['Article']] = None

    @classmethod
    def from_db(cls, o: models.Category, full=False) -> 'Category':
        if full:
            tasks = [Task.from_db(t) for t in o.tasks]
            articles = [Article.from_db(a) for a in o.articles]
        else:
            tasks, articles = None, None
        return cls(
            id=o.id,
            name=o.name,
            tasks=tasks,
            articles=articles
        )


@dataclass()
class Task(_BaseAPIModel):
    title: str
    category: Category
    points: int
    description: str
    is_proposal: bool
    author: User
    writeup: Optional[str] = None
    flag: Optional[str] = None
    files: Optional[List[File]] = None
    solved_by: Optional[List[User]] = None

    @classmethod
    def from_db(cls, o: models.Task, full=False) -> 'Task':
        if full:
            files = [File.from_db(file) for file in o.files]
            solved_by = [User.from_db(user) for user in o.solved]
        else:
            files, solved_by = None, None
        return cls(
            id=o.id,
            title=o.title,
            category=Category.from_db(o.category),
            points=o.points,
            description=o.description,
            is_proposal=o.is_proposal,
            author=User.from_db(o.author),
            files=files,
            solved_by=solved_by
        )


@dataclass()
class Article(_BaseAPIModel):
    title: str
    text: str
    category: Category

    @classmethod
    def from_db(cls, o: models.Article, full=False) -> 'Article':
        return cls(
            id=o.id,
            title=o.title,
            text=o.text,
            category=Category.from_db(o.category)
        )
