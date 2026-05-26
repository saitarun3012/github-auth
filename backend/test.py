import pytest
from httpx import AsyncClient, ASGITransport
from main import app

@pytest.mark.anyio
async def test_register_success():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.post("/register", json={
            "name": "Test User",
            "email": "testuser123@gmail.com",
            "password": "testpass123"
        })
    assert response.status_code == 200
    assert "message" in response.json()