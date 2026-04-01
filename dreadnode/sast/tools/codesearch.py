"""
CodeSearch sub-agent tool.

Provides natural language code exploration by spawning a specialized
sub-agent with limited tools focused on code search and analysis.
"""

from dreadnode.agents import Agent
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.core.meta import Config
from dreadnode.tools import glob, grep, read, ls
from loguru import logger


CODESEARCH_INSTRUCTIONS = """
You are a specialized code exploration agent designed to search and analyze codebases
to answer natural language questions about code structure, patterns, and specific implementations.

YOUR GOAL:
Given a query about a codebase, systematically explore the code to find relevant files,
functions, and patterns, then provide a concise writeup of your findings.

EXPLORATION WORKFLOW:

1. UNDERSTAND THE QUERY
   - Identify what the user is looking for (files, functions, patterns, data flow, etc.)
   - Determine likely file types, naming conventions, and locations

2. ORIENT YOURSELF
   - Use `ls` to understand the project structure if needed
   - Use `glob` to find files matching likely patterns (e.g., "**/*.py", "**/auth*")

3. SEARCH STRATEGICALLY
   - Use `grep` to find specific patterns, function names, class definitions
   - Search for imports, function calls, variable names related to the query
   - Look for configuration files, entry points, and key modules

4. READ AND ANALYZE
   - Use `read` to examine promising files
   - Follow imports and function calls to trace data flow
   - Note file paths and line numbers for important findings

5. SYNTHESIZE FINDINGS
   - Compile a clear, structured summary of what you found
   - Include specific file paths and line numbers
   - Highlight the most relevant code sections
   - Note any patterns, potential issues, or points of interest

SEARCH STRATEGIES BY QUERY TYPE:

For "Where is X implemented?":
- Grep for class/function definitions: "class X", "def X", "function X"
- Check common locations: src/, lib/, core/, utils/

For "How does X work?":
- Find the implementation, then trace callers and callees
- Read related tests for usage examples
- Check for documentation or comments

For "Find all X" (sources, sinks, patterns):
- Use grep with appropriate regex patterns
- Search across all relevant file types
- Group findings by file/module

For "What calls X?" or "What does X call?":
- Grep for the function/method name
- Read surrounding context to understand call sites
- Trace the call graph manually if needed

OUTPUT FORMAT:
Provide a structured writeup with:
- Summary of findings (2-3 sentences)
- Key files and their relevance
- Specific code locations (file:line) for important findings
- Any patterns or concerns noticed

Be thorough but concise. The parent agent needs actionable information, not exhaustive dumps.
"""


class CodeSearchTool(Toolset):
    """
    A sub-agent tool for natural language code exploration.

    Spawns a specialized agent that systematically searches codebases to answer
    questions about code structure, implementations, data flow, and patterns.
    """

    model: str = Config(default="anthropic/claude-sonnet-4-20250514")
    """Model to use for the codesearch sub-agent."""

    max_steps: int = Config(default=15)
    """Maximum steps for the codesearch sub-agent."""

    def _create_agent(self) -> Agent:
        """Create the codesearch agent with configured model."""
        return Agent(
            name="CodeSearch Agent",
            instructions=CODESEARCH_INSTRUCTIONS,
            model=self.model,
            tools=[glob, grep, read, ls],
            max_steps=self.max_steps,
        )

    @tool_method(catch=True)
    async def codesearch(self, query: str, path: str = ".") -> str:
        """
        Search a codebase using natural language to find relevant files and code patterns.

        Spawns a specialized code exploration agent that systematically searches
        the codebase to answer questions about code structure, implementations,
        data flow, and patterns. Use this for open-ended exploration when you need
        to understand how something works or find specific code patterns.

        Args:
            query: Natural language description of what to find (e.g., "Find all SQL
                query construction", "Where is user authentication implemented?",
                "What functions handle file uploads?").
            path: Base directory to search in. Defaults to current working directory.

        Returns:
            A structured writeup of findings including relevant files, code locations,
            and analysis of the discovered patterns.
        """
        logger.info(f"CodeSearch: Starting search for '{query[:50]}...' in {path}")

        agent = self._create_agent()

        prompt = f"""
Search the codebase at '{path}' to answer the following query:

{query}

Explore systematically, search for relevant patterns, read key files, and provide
a clear writeup of your findings with specific file paths and line numbers.
"""

        try:
            trajectory = await agent.run(prompt)

            # Extract the final response from the trajectory
            if trajectory.messages:
                # Get the last assistant message
                for msg in reversed(trajectory.messages):
                    if msg.role == "assistant" and msg.content:
                        content = msg.content
                        result = content if isinstance(content, str) else str(content)
                        logger.info(
                            f"CodeSearch: Completed in {len(trajectory.steps)} steps, "
                            f"{trajectory.usage.total_tokens} tokens"
                        )
                        return result

            # Fallback if no assistant message found
            logger.warning("CodeSearch: No assistant response found in trajectory")
            return "CodeSearch completed but produced no output."

        except Exception as e:
            logger.error(f"CodeSearch failed: {e}")
            return f"CodeSearch failed: {e}"
