def handler(event, context):
    return {
        'statusCode': 200,
        'body': '{"status": "healthy", "message": "API working"}'
    }
