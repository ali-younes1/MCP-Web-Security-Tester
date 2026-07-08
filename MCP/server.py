import json
import time
from dataclasses import dataclass
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from playwright.async_api import Browser, BrowserContext, Page, async_playwright


BrowserName = Literal["chromium", "firefox", "webkit"]


@dataclass
class BrowserSession:
    id: str
    browser: Browser
    context: BrowserContext
    page: Page
    browser_type: BrowserName


class InjectionEvidenceAnalyzer:
    @staticmethod
    def analyze(
        baseline: dict[str, Any],
        test_result: dict[str, Any],
        payload: str,
    ) -> dict[str, Any]:
        evidence: list[str] = []
        behaviors: list[str] = []

        is_vulnerable = False
        confidence: Literal["high", "medium", "low", "none"] = "none"
        recommendation = ""

        time_diff = test_result["time"] - baseline["time"]
        length_diff = abs(len(test_result["body"]) - len(baseline["body"]))

        nosql_operators = [
            "$gt",
            "$lt",
            "$ne",
            "$eq",
            "$regex",
            "$where",
            "$exists",
            "$in",
            "$nin",
        ]

        has_nosql_operator = any(op in payload for op in nosql_operators)

        if has_nosql_operator or ("{" in payload and "}" in payload):
            if baseline["status"] in [401, 403] and test_result["status"] == 200:
                is_vulnerable = True
                confidence = "high"
                evidence.append(
                    f"NoSQL Injection: Authentication bypassed "
                    f"({baseline['status']} → 200)"
                )
                behaviors.append("NOSQL_AUTH_BYPASS")
                recommendation = (
                    "High confidence NoSQL injection indicator. "
                    "Collect limited evidence and recommend strict input validation "
                    "plus safe query construction."
                )

            if length_diff > 200 and test_result["status"] == 200:
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"
                    evidence.append(
                        "NoSQL Injection: Significant data returned with operator payload"
                    )
                    behaviors.append("NOSQL_DATA_EXTRACTION")
                    recommendation = (
                        recommendation
                        or "Potential NoSQL injection. Operator payload returned different data."
                    )

            nosql_errors = [
                "mongodb",
                "mongoose",
                "invalid operator",
                "$where",
                "query error",
            ]

            for error in nosql_errors:
                if (
                    error in test_result["body"].lower()
                    and error not in baseline["body"].lower()
                ):
                    if confidence == "none":
                        is_vulnerable = True
                        confidence = "medium"
                        evidence.append(f"NoSQL error detected: {error}")
                        behaviors.append("NOSQL_ERROR_MESSAGE")
                        recommendation = (
                            recommendation
                            or "Potential NoSQL injection. Database error was exposed."
                        )
                    break

        sql_errors = [
            "sql syntax",
            "mysql_",
            "postgresql",
            "ora-",
            "sqlite",
            "mssql",
            "unclosed quotation",
            "quoted string not properly terminated",
            "syntax error",
            "database error",
            "warning: mysql",
            "pg_query",
            "odbc",
            "jdbc",
            "oracle error",
        ]

        if not is_vulnerable:
            for error in sql_errors:
                if error in test_result["body"].lower():
                    is_vulnerable = True
                    confidence = "high"
                    evidence.append(f'SQL error message detected: "{error}"')
                    behaviors.append("SQL_ERROR_MESSAGE")
                    recommendation = (
                        "High confidence SQL injection indicator. "
                        "Recommend parameterized queries and server-side input validation."
                    )
                    break

        if not is_vulnerable and payload in test_result["body"]:
            is_encoded_or_filtered = (
                payload.replace("<", "&lt;") in test_result["body"]
                or payload.replace("<", "&#60;") in test_result["body"]
            )

            if (
                not is_encoded_or_filtered
                and (
                    "<" in payload
                    or "script" in payload.lower()
                    or "onerror" in payload.lower()
                )
            ):
                is_vulnerable = True
                confidence = "high"
                evidence.append("Payload reflected in response without proper encoding")
                behaviors.append("XSS_REFLECTION_UNENCODED")
                recommendation = (
                    "High confidence XSS indicator. "
                    "Payload is reflected without proper encoding."
                )

            elif is_encoded_or_filtered:
                evidence.append("Payload reflected but appears to be encoded/filtered")
                behaviors.append("XSS_REFLECTION_ENCODED")
                recommendation = (
                    "Payload is reflected but encoded. "
                    "The application may be filtering or encoding the input."
                )

        if time_diff > 4000:
            is_vulnerable = True
            confidence = "high" if confidence == "high" else "medium"
            evidence.append(
                f"Response delayed by {time_diff}ms "
                f"(baseline: {baseline['time']}ms)"
            )
            behaviors.append("TIME_BASED_DELAY")
            recommendation = (
                recommendation
                or "Potential time-based injection. Verify with another safe proof payload."
            )

        if test_result["status"] != baseline["status"]:
            behaviors.append(
                f"STATUS_CODE_CHANGE ({baseline['status']} → {test_result['status']})"
            )
            evidence.append(
                f"Status code changed from {baseline['status']} "
                f"to {test_result['status']}"
            )

            if test_result["status"] == 500:
                is_vulnerable = True
                confidence = "medium" if confidence == "none" else confidence
                evidence.append("Server returned 500 Internal Server Error")
                behaviors.append("SERVER_ERROR")
                recommendation = (
                    recommendation
                    or "Server error triggered. Application may be vulnerable."
                )

            elif test_result["status"] in [403, 406]:
                evidence.append("Payload was blocked by WAF or security filter")
                behaviors.append("INPUT_FILTER_DETECTED")
                recommendation = recommendation or "Input appears to be filtered or blocked."

        if length_diff > 100:
            behaviors.append(f"RESPONSE_LENGTH_CHANGE ({length_diff} bytes)")
            evidence.append(f"Response length changed by {length_diff} bytes")

            if length_diff > 1000 and not is_vulnerable:
                recommendation = (
                    recommendation
                    or "Significant response change detected. Inspect manually."
                )

        if not is_vulnerable and len(evidence) == 0:
            recommendation = (
                "No vulnerability indicators detected. "
                "Try a different authorized test input or inspect manually."
            )

        return {
            "isVulnerable": is_vulnerable,
            "confidence": confidence,
            "evidence": evidence,
            "detectedBehaviors": behaviors,
            "responseAnalysis": {
                "statusCode": test_result["status"],
                "responseTime": test_result["time"],
                "baselineTime": baseline["time"],
                "timeDifference": time_diff,
                "responseLengthChange": length_diff,
            },
            "recommendation": recommendation,
        }


class BrowserManager:
    def __init__(self) -> None:
        self.playwright = None
        self.sessions: dict[str, BrowserSession] = {}

    async def start_playwright(self):
        if self.playwright is None:
            self.playwright = await async_playwright().start()
        return self.playwright

    async def get_or_create_session(
        self,
        session_id: str = "default",
        browser: BrowserName = "chromium",
        viewport: dict[str, int] | None = None,
    ) -> BrowserSession:
        if session_id in self.sessions:
            return self.sessions[session_id]

        pw = await self.start_playwright()

        if browser == "firefox":
            browser_instance = await pw.firefox.launch(headless=False)
        elif browser == "webkit":
            browser_instance = await pw.webkit.launch(headless=False)
        else:
            browser_instance = await pw.chromium.launch(headless=False)

        context = await browser_instance.new_context(
            viewport=viewport or {"width": 1280, "height": 720}
        )
        page = await context.new_page()

        session = BrowserSession(
            id=session_id,
            browser=browser_instance,
            context=context,
            page=page,
            browser_type=browser,
        )

        self.sessions[session_id] = session
        return session

    def get_session(self, session_id: str = "default") -> BrowserSession:
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        return self.sessions[session_id]

    async def close_session(self, session_id: str = "default") -> None:
        session = self.get_session(session_id)
        await session.browser.close()
        del self.sessions[session_id]


manager = BrowserManager()
mcp = FastMCP("mcp-authorized-web-pentest")


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


@mcp.tool()
async def open_page(
    url: str,
    waitFor: Literal["load", "domcontentloaded", "networkidle"] = "load",
    sessionId: str = "default",
    browser: BrowserName = "chromium",
    viewport: dict[str, int] | None = None,
) -> str:
    """Navigate to a URL in the browser."""
    session = await manager.get_or_create_session(sessionId, browser, viewport)

    await session.page.goto(url, wait_until=waitFor)

    return to_json(
        {
            "success": True,
            "url": session.page.url,
            "title": await session.page.title(),
            "sessionId": sessionId,
        }
    )


@mcp.tool()
async def click_element(
    selector: str,
    sessionId: str = "default",
    waitFor: int = 1000,
    force: bool = False,
) -> str:
    """Click on an element."""
    session = manager.get_session(sessionId)

    await session.page.click(selector, force=force)

    if waitFor > 0:
        await session.page.wait_for_timeout(waitFor)

    return to_json(
        {
            "success": True,
            "action": "click",
            "selector": selector,
        }
    )


@mcp.tool()
async def type_text(
    selector: str,
    text: str,
    sessionId: str = "default",
    clear: bool = True,
    delay: int = 50,
) -> str:
    """Type text into an element."""
    session = manager.get_session(sessionId)

    if clear:
        await session.page.fill(selector, "")

    await session.page.type(selector, text, delay=delay)

    shown_text = text[:100] + ("..." if len(text) > 100 else "")

    return to_json(
        {
            "success": True,
            "action": "type",
            "selector": selector,
            "text": shown_text,
        }
    )


@mcp.tool()
async def capture_screenshot(
    path: str,
    sessionId: str = "default",
    selector: str | None = None,
    fullPage: bool = False,
    type: Literal["png", "jpeg"] | None = None,
    quality: int = 90,
) -> str:
    """Take a screenshot of the page or element."""
    session = manager.get_session(sessionId)

    file_type = type
    if file_type is None:
        lower_path = path.lower()
        file_type = "jpeg" if lower_path.endswith(".jpg") or lower_path.endswith(".jpeg") else "png"

    options: dict[str, Any] = {
        "path": path,
        "type": file_type,
    }

    if file_type == "jpeg":
        options["quality"] = quality

    if selector:
        await session.page.locator(selector).screenshot(**options)
    else:
        options["full_page"] = fullPage
        await session.page.screenshot(**options)

    return to_json(
        {
            "success": True,
            "action": "screenshot",
            "path": path,
            "type": file_type,
            "fullPage": fullPage,
            "selector": selector,
            "quality": quality if file_type == "jpeg" else None,
        }
    )


@mcp.tool()
async def read_element(
    selector: str,
    sessionId: str = "default",
    attribute: str | None = None,
    multiple: bool = False,
) -> str:
    """Extract text content from elements."""
    session = manager.get_session(sessionId)

    locator = session.page.locator(selector)

    if multiple:
        results = []
        count = await locator.count()

        for i in range(count):
            element = locator.nth(i)
            value = await element.get_attribute(attribute) if attribute else await element.text_content()
            results.append(value)

        result: Any = results
    else:
        result = await locator.get_attribute(attribute) if attribute else await locator.text_content()

    return to_json(
        {
            "success": True,
            "action": "extract_text",
            "selector": selector,
            "attribute": attribute,
            "result": result,
        }
    )


@mcp.tool()
async def wait_for_element(
    selector: str,
    sessionId: str = "default",
    timeout: int = 30000,
    state: Literal["visible", "hidden", "attached", "detached"] = "visible",
) -> str:
    """Wait for an element to appear."""
    session = manager.get_session(sessionId)

    await session.page.wait_for_selector(selector, timeout=timeout, state=state)

    return to_json(
        {
            "success": True,
            "action": "wait_for_element",
            "selector": selector,
            "state": state,
            "timeout": timeout,
        }
    )


@mcp.tool()
async def fill_form(
    fields: dict[str, str],
    sessionId: str = "default",
    submitSelector: str | None = None,
    waitAfterSubmit: int = 3000,
) -> str:
    """Fill out a form with multiple fields."""
    session = manager.get_session(sessionId)

    for selector, value in fields.items():
        await session.page.fill(selector, value)

    if submitSelector:
        await session.page.click(submitSelector)

        if waitAfterSubmit > 0:
            await session.page.wait_for_timeout(waitAfterSubmit)

    return to_json(
        {
            "success": True,
            "action": "fill_form",
            "fieldsCount": len(fields),
            "submitted": submitSelector is not None,
        }
    )


@mcp.tool()
async def scroll(
    direction: Literal["up", "down", "left", "right", "top", "bottom"] = "down",
    pixels: int = 500,
    sessionId: str = "default",
    selector: str | None = None,
) -> str:
    """Scroll the page."""
    session = manager.get_session(sessionId)

    params = {"direction": direction, "pixels": pixels}

    if selector:
        await session.page.locator(selector).evaluate(
            """
            (el, params) => {
                const direction = params.direction;
                const pixels = params.pixels;

                if (direction === "up") el.scrollTop -= pixels;
                if (direction === "down") el.scrollTop += pixels;
                if (direction === "left") el.scrollLeft -= pixels;
                if (direction === "right") el.scrollLeft += pixels;
                if (direction === "top") el.scrollTop = 0;
                if (direction === "bottom") el.scrollTop = el.scrollHeight;
            }
            """,
            params,
        )
    else:
        await session.page.evaluate(
            """
            (params) => {
                const direction = params.direction;
                const pixels = params.pixels;

                if (direction === "up") window.scrollBy(0, -pixels);
                if (direction === "down") window.scrollBy(0, pixels);
                if (direction === "left") window.scrollBy(-pixels, 0);
                if (direction === "right") window.scrollBy(pixels, 0);
                if (direction === "top") window.scrollTo(0, 0);
                if (direction === "bottom") window.scrollTo(0, document.body.scrollHeight);
            }
            """,
            params,
        )

    return to_json(
        {
            "success": True,
            "action": "scroll",
            "direction": direction,
            "pixels": pixels,
        }
    )


@mcp.tool()
async def page_info(
    sessionId: str = "default",
    includeMetrics: bool = False,
) -> str:
    """Get current page information."""
    session = manager.get_session(sessionId)

    info: dict[str, Any] = {
        "url": session.page.url,
        "title": await session.page.title(),
        "viewport": session.page.viewport_size,
    }

    if includeMetrics:
        metrics = await session.page.evaluate(
            """
            () => ({
                loadTime:
                    performance.timing.loadEventEnd -
                    performance.timing.navigationStart,
                domContentLoaded:
                    performance.timing.domContentLoadedEventEnd -
                    performance.timing.navigationStart,
                domElements: document.querySelectorAll("*").length
            })
            """
        )

        info["metrics"] = metrics

    return to_json(
        {
            "success": True,
            "info": info,
        }
    )


@mcp.tool()
async def run_dom_check(
    script: str,
    sessionId: str = "default",
    args: list[Any] | None = None,
) -> str:
    """Execute JavaScript on the page."""
    session = manager.get_session(sessionId)

    script_args = args or []

    result = await session.page.evaluate(
        """
        ({ script, args }) => {
            const func = new Function("...args", script);
            return func(...args);
        }
        """,
        {
            "script": script,
            "args": script_args,
        },
    )

    return to_json(
        {
            "success": True,
            "result": result,
        }
    )


@mcp.tool()
async def close_session(sessionId: str = "default") -> str:
    """Close a browser session."""
    await manager.close_session(sessionId)

    return to_json(
        {
            "success": True,
            "action": "close_session",
            "sessionId": sessionId,
        }
    )


@mcp.tool()
async def test_injection_payload(
    targetSelector: str,
    payload: str,
    sessionId: str = "default",
    submitSelector: str | None = None,
    waitAfterSubmit: int = 2000,
) -> str:
    """
    
    Test one authorized injection payload against one input field and compare
    the normal page behavior with the test result.

    The LLM should:
    1. Open the target page.
    2. Identify the relevant input field.
    3. Test one payload at a time.
    4. Review evidence, confidence, and recommendation.
    5. Adapt the next test based on the result.
    6. Collect DOM, browser, or screenshot evidence when a finding is confirmed.
    7. Stop after confirming the requested vulnerability.

    Supported testing focus:
    - SQL injection indicators
    - NoSQL injection indicators
    - XSS reflection and DOM execution indicators
    - Time-based response delays
    - Status code or response length changes

    Use only on applications the user owns or is authorized to test.

    """
    session = manager.get_session(sessionId)

    try:
        baseline_start = time.perf_counter()

        await session.page.fill(targetSelector, "safetest123")

        if submitSelector:
            await session.page.click(submitSelector)
            await session.page.wait_for_timeout(waitAfterSubmit)

        baseline_body = await session.page.content()
        baseline_time = int((time.perf_counter() - baseline_start) * 1000)
        baseline_status = 200

        test_start = time.perf_counter()

        await session.page.fill(targetSelector, "")
        await session.page.fill(targetSelector, payload)

        if submitSelector:
            await session.page.click(submitSelector)
            await session.page.wait_for_timeout(waitAfterSubmit)

        test_body = await session.page.content()
        test_time = int((time.perf_counter() - test_start) * 1000)
        test_status = 200

        analysis = InjectionEvidenceAnalyzer.analyze(
            {
                "status": baseline_status,
                "body": baseline_body,
                "time": baseline_time,
            },
            {
                "status": test_status,
                "body": test_body,
                "time": test_time,
            },
            payload,
        )

        result = {
            "success": True,
            "payload": payload,
            **analysis,
        }

        return to_json(result)

    except Exception as error:
        return to_json(
            {
                "success": False,
                "payload": payload,
                "error": str(error),
                "recommendation": (
                    "Error executing payload. "
                    "Check selector validity and page state."
                ),
            }
        )


if __name__ == "__main__":
    mcp.run()