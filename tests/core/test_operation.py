from signify.core.api import Operation

def test_pending_operation_omits_result_fields():
    op = Operation(name="oobi.example", metadata={}, done=False)
    assert op.error is None
    assert op.response is None

def test_completed_operation_preserves_result():
    result = {"i": "example"}
    op = Operation(name="oobi.example", metadata={}, done=True, error=None, response=result)
    assert op.response == result
