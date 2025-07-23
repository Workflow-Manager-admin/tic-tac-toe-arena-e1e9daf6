from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import sqlite3
import uuid
import os

# For demonstration purposes, use SECRET_KEY from environment or default (in production, always set securely)
SECRET_KEY = os.environ.get("SECRET_KEY", "tictacsupersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Database setup ---
DB_PATH = os.environ.get("DB_PATH", "tic_tac_toe.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT
    )
    """)
    # Games table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS games (
        id TEXT PRIMARY KEY,
        player_x TEXT NOT NULL,
        player_o TEXT,
        is_vs_ai INTEGER NOT NULL,
        winner TEXT,
        board TEXT NOT NULL,
        moves TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT,
        finished_at TEXT,
        FOREIGN KEY(player_x) REFERENCES users(id),
        FOREIGN KEY(player_o) REFERENCES users(id)
    )
    """)
    # Leaderboards table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS leaderboards (
        user_id TEXT PRIMARY KEY,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        draws INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Auth setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

class User(BaseModel):
    id: str
    username: str
    email: EmailStr
    created_at: Optional[str]

class UserCreate(BaseModel):
    username: str = Field(..., description="Unique user name")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password for the user")

class UserProfile(BaseModel):
    username: str
    email: EmailStr
    wins: int
    losses: int
    draws: int

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email_or_username(identifier: str) -> Optional[User]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=? OR username=?", (identifier, identifier))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(id=row["id"], username=row["username"], email=row["email"], created_at=row["created_at"])
    return None

def get_user_from_id(user_id: str) -> Optional[User]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(id=row["id"], username=row["username"], email=row["email"], created_at=row["created_at"])
    return None

def authenticate_user(identifier: str, password: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    if user and verify_password(password, user["password_hash"]):
        return User(id=user["id"], username=user["username"], email=user["email"], created_at=user["created_at"])
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_from_id(user_id)
    if user is None:
        raise credentials_exception
    return user

# --- Game logic ---
class Move(BaseModel):
    x: int = Field(..., ge=0, le=2)
    y: int = Field(..., ge=0, le=2)
    player: str

class GameBoard(BaseModel):
    board: List[List[str]] = Field(..., description='3x3 board, X/O/empty')
    next_turn: str
    moves: List[Dict] = Field(default_factory=list)

class GameCreate(BaseModel):
    opponent: Optional[str] = Field(None, description='User ID or "AI"')
    as_x: Optional[bool] = Field(True, description='Play as X (True) or O (False)')

class GameInfo(BaseModel):
    game_id: str
    vs_ai: bool
    player_x: str
    player_o: Optional[str]
    board: List[List[str]]
    moves: List[Dict]
    status: str
    winner: Optional[str]
    created_at: str
    finished_at: Optional[str]

class MoveRequest(BaseModel):
    x: int = Field(..., ge=0, le=2)
    y: int = Field(..., ge=0, le=2)

class LeaderboardEntry(BaseModel):
    username: str
    wins: int
    losses: int
    draws: int

# Game status: waiting, in_progress, finished

def empty_board():
    return [["" for _ in range(3)] for _ in range(3)]

def serialize_board(board):
    return ",".join("".join(row) for row in board)

def unserialize_board(serialized):
    cells = list(serialized)
    return [cells[i*3:(i+1)*3] for i in range(3)]

def valid_move(board, x, y):
    return board[y][x] == ""

def apply_move(board, x, y, symbol):
    board[y][x] = symbol
    return board

def check_winner(board):
    lines = []
    for row in board:
        lines.append(row)
    for col in zip(*board):
        lines.append(list(col))
    lines.append([board[i][i] for i in range(3)])
    lines.append([board[i][2 - i] for i in range(3)])
    for line in lines:
        if line[0] and all(cell == line[0] for cell in line):
            return line[0]
    if all(cell for row in board for cell in row):
        return "draw"
    return None

def ai_make_move(board, symbol):
    # Simple AI: Pick first empty cell
    for i in range(3):
        for j in range(3):
            if board[i][j] == "":
                return i, j
    return None, None

# --- FastAPI app setup ---
app = FastAPI(
    title="Tic Tac Toe Arena API",
    description="API for multiplayer Tic Tac Toe, authentication, leaderboards, and history",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "Authentication and user management"},
        {"name": "users", "description": "User profile endpoints"},
        {"name": "game", "description": "Tic Tac Toe game API"},
        {"name": "history", "description": "Move and game history"},
        {"name": "leaderboards", "description": "Leaderboards"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# ---- AUTHENTICATION ----
# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=Token, tags=["auth"], summary="Register new user")
def register_user(user: UserCreate):
    """Register a new user. Returns access token on success."""
    conn = get_db()
    cursor = conn.cursor()
    user_id = str(uuid.uuid4())
    try:
        cursor.execute(
            "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                user.username,
                user.email,
                get_password_hash(user.password),
                datetime.utcnow().isoformat(),
            ),
        )
        # Also create leaderboard record
        cursor.execute(
            "INSERT INTO leaderboards (user_id, wins, losses, draws) VALUES (?, 0, 0, 0)",
            (user_id,)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    finally:
        conn.close()
    access_token = create_access_token(data={"sub": user_id})
    return Token(access_token=access_token)

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["auth"], summary="User login / token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate and get access token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username/email or password")
    access_token = create_access_token(data={"sub": user.id})
    return Token(access_token=access_token)

# ---- USER PROFILE ----
# PUBLIC_INTERFACE
@app.get("/users/me", response_model=UserProfile, tags=["users"], summary="Get own profile")
async def get_own_profile(current_user: User = Depends(get_current_user)):
    """Fetch current user's profile and stats"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM leaderboards WHERE user_id=?", (current_user.id,))
    rec = cursor.fetchone()
    conn.close()
    if rec:
        return UserProfile(
            username=current_user.username,
            email=current_user.email,
            wins=rec["wins"],
            losses=rec["losses"],
            draws=rec["draws"]
        )
    else:
        return UserProfile(
            username=current_user.username,
            email=current_user.email,
            wins=0, losses=0, draws=0
        )

# ---- GAME CREATION ----
# PUBLIC_INTERFACE
@app.post("/games", response_model=GameInfo, tags=["game"], summary="Start new game")
async def start_game(game: GameCreate, current_user: User = Depends(get_current_user)):
    """
    Create a new Tic Tac Toe game.
    - If 'opponent' is not given or is 'AI', starts a game vs AI.
    - If 'opponent' is a user ID, starts a PVP game as `X` (unless `as_x`=False).
    """
    if not game.opponent or game.opponent.lower() == "ai":
        # User vs AI
        game_id = str(uuid.uuid4())
        board = empty_board()
        board_str = serialize_board(board)
        now = datetime.utcnow().isoformat()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO games (id, player_x, player_o, is_vs_ai, winner, board, moves, status, created_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                game_id,
                current_user.id,
                None,
                1,
                None,
                board_str,
                "[]",
                "in_progress",
                now,
                None
            )
        )
        conn.commit()
        conn.close()
        return GameInfo(
            game_id=game_id, vs_ai=True, player_x=current_user.username, player_o=None,
            board=board, moves=[], status="in_progress", winner=None, created_at=now, finished_at=None
        )
    else:
        # User vs User
        opp = get_user_from_id(game.opponent)
        if not opp:
            raise HTTPException(status_code=404, detail="Opponent not found")
        if game.as_x:
            player_x, player_o = current_user.id, opp.id
        else:
            player_x, player_o = opp.id, current_user.id
        game_id = str(uuid.uuid4())
        board = empty_board()
        board_str = serialize_board(board)
        now = datetime.utcnow().isoformat()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO games (id, player_x, player_o, is_vs_ai, winner, board, moves, status, created_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                game_id,
                player_x,
                player_o,
                0,
                None,
                board_str,
                "[]",
                "waiting",
                now,
                None
            )
        )
        conn.commit()
        conn.close()
        return GameInfo(
            game_id=game_id, vs_ai=False, player_x=player_x, player_o=player_o,
            board=board, moves=[], status="waiting", winner=None, created_at=now, finished_at=None
        )

# PUBLIC_INTERFACE
@app.get("/games/mine", response_model=List[GameInfo], tags=["game"], summary="List my games")
async def list_my_games(current_user: User = Depends(get_current_user)):
    """List active and recently played games for the current user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM games WHERE player_x=? OR player_o=? ORDER BY created_at DESC LIMIT 20
        """, (current_user.id, current_user.id)
    )
    recs = cursor.fetchall()
    conn.close()
    result = []
    for r in recs:
        result.append(GameInfo(
            game_id=r["id"],
            vs_ai=bool(r["is_vs_ai"]),
            player_x=r["player_x"],
            player_o=r["player_o"],
            board=unserialize_board(r["board"]),
            moves=eval(r["moves"]),
            status=r["status"],
            winner=r["winner"],
            created_at=r["created_at"],
            finished_at=r["finished_at"]
        ))
    return result

# ---- GAME ACTIONS ----
# PUBLIC_INTERFACE
@app.post("/games/{game_id}/move", response_model=GameInfo, tags=["game"], summary="Make move")
async def make_move(game_id: str, move: MoveRequest, current_user: User = Depends(get_current_user)):
    """
    Make a move in a game. Returns updated game state.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM games WHERE id=?", (game_id,))
    game = cursor.fetchone()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    # Load board and moves
    board = unserialize_board(game["board"])
    moves = eval(game["moves"])
    # Determine symbol for this user
    symbol = None
    if game["player_x"] == current_user.id:
        symbol = "X"
    elif game["player_o"] == current_user.id or (game["is_vs_ai"] and game["player_o"] is None):
        symbol = "O"
    else:
        raise HTTPException(status_code=403, detail="Not a player in this game")
    # Check turn
    if moves and ((moves[-1]["player"] == "X" and symbol == "X") or (moves[-1]["player"] == "O" and symbol == "O")):
        raise HTTPException(status_code=403, detail="Not your turn yet")
    if not valid_move(board, move.x, move.y):
        raise HTTPException(status_code=400, detail="Invalid move position")
    apply_move(board, move.x, move.y, symbol)
    moves.append({"x": move.x, "y": move.y, "player": symbol})
    winner = check_winner(board)
    finished = winner is not None
    conn2 = get_db()
    cursor2 = conn2.cursor()
    # AI move if applicable and not finished
    if not finished and bool(game["is_vs_ai"]) and symbol == "X":
        ai_x, ai_y = ai_make_move(board, "O")
        if ai_x is not None and ai_y is not None:
            apply_move(board, ai_y, ai_x, "O")
            moves.append({"x": ai_y, "y": ai_x, "player": "O"})
            winner = check_winner(board)
            finished = winner is not None
    update_kwargs = {
        "board": serialize_board(board),
        "moves": repr(moves),
        "status": "finished" if finished else "in_progress",
        "winner": winner if finished and winner != "draw" else None,
        "finished_at": datetime.utcnow().isoformat() if finished else None
    }
    set_clause = ", ".join(f"{k}=?" for k in update_kwargs)
    update_vals = list(update_kwargs.values()) + [game_id]
    cursor2.execute(f"UPDATE games SET {set_clause} WHERE id=?", update_vals)
    # Update leaderboard if finished
    if finished:
        # Only update for real users, not for games with None
        px, po = game["player_x"], game["player_o"]
        if winner == "draw":
            for uid in [px, po]:
                if uid:
                    cursor2.execute("UPDATE leaderboards SET draws = draws + 1 WHERE user_id=?", (uid,))
        elif winner == "X":
            if px:
                cursor2.execute("UPDATE leaderboards SET wins = wins + 1 WHERE user_id=?", (px,))
            if po:
                cursor2.execute("UPDATE leaderboards SET losses = losses + 1 WHERE user_id=?", (po,))
        elif winner == "O":
            if po:
                cursor2.execute("UPDATE leaderboards SET wins = wins + 1 WHERE user_id=?", (po,))
            if px:
                cursor2.execute("UPDATE leaderboards SET losses = losses + 1 WHERE user_id=?", (px,))
    conn2.commit()
    conn2.close()
    conn.close()
    return GameInfo(
        game_id=game["id"],
        vs_ai=bool(game["is_vs_ai"]),
        player_x=game["player_x"],
        player_o=game["player_o"],
        board=board,
        moves=moves,
        status="finished" if finished else "in_progress",
        winner=winner if finished else None,
        created_at=game["created_at"],
        finished_at=datetime.utcnow().isoformat() if finished else None
    )

# PUBLIC_INTERFACE
@app.get("/games/{game_id}", response_model=GameInfo, tags=["game"], summary="Get game state")
async def get_game(game_id: str, current_user: User = Depends(get_current_user)):
    """Retrieve a game state by ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM games WHERE id=?", (game_id,))
    game = cursor.fetchone()
    conn.close()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    # Only allow players to see game
    if game["player_x"] != current_user.id and (game["player_o"] or game["is_vs_ai"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Not permitted")
    return GameInfo(
        game_id=game["id"],
        vs_ai=bool(game["is_vs_ai"]),
        player_x=game["player_x"],
        player_o=game["player_o"],
        board=unserialize_board(game["board"]),
        moves=eval(game["moves"]),
        status=game["status"],
        winner=game["winner"],
        created_at=game["created_at"],
        finished_at=game["finished_at"]
    )

# ---- LEADERBOARDS ----
# PUBLIC_INTERFACE
@app.get("/leaderboards", response_model=List[LeaderboardEntry], tags=["leaderboards"], summary="View leaderboard")
async def get_leaderboard():
    """Get top players by number of wins."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT u.username, l.wins, l.losses, l.draws FROM leaderboards l
    JOIN users u ON u.id = l.user_id
    ORDER BY l.wins DESC, l.draws DESC, l.losses ASC LIMIT 20
    """)
    recs = cursor.fetchall()
    conn.close()
    return [LeaderboardEntry(username=r["username"], wins=r["wins"], losses=r["losses"], draws=r["draws"]) for r in recs]

# ---- GAME HISTORY ----
# PUBLIC_INTERFACE
@app.get("/history/moves/{game_id}", tags=["history"], summary="Get move history")
async def get_move_history(game_id: str, current_user: User = Depends(get_current_user)):
    """Retrieve the move history for a given game."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM games WHERE id=?", (game_id,))
    game = cursor.fetchone()
    conn.close()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    # Player access only
    if game["player_x"] != current_user.id and (game["player_o"] or game["is_vs_ai"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Not permitted")
    moves = eval(game["moves"])
    return {"game_id": game_id, "moves": moves}

# ---- USER LIST FOR CHALLENGE ----
# PUBLIC_INTERFACE
@app.get("/users", response_model=List[User], tags=["users"], summary="Get list of users")
async def list_users(current_user: User = Depends(get_current_user)):
    """List other registered users for PVP."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id!=?", (current_user.id,))
    recs = cursor.fetchall()
    conn.close()
    return [User(id=u["id"], username=u["username"], email=u["email"], created_at=u["created_at"]) for u in recs]
