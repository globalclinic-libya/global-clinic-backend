import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_status(client):
    rv = client.get('/api/status')
    assert rv.status_code == 200
    json_data = rv.get_json()
    assert json_data['status'] == 'healthy'
