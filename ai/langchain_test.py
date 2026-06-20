from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser


def main():
    llm = ChatOllama(
        model="llama3.1:8b",
        base_url="http://localhost:11434",
        temperature=0.1,
    )

    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            "너는 보안 보고서를 작성하는 도우미이다. 답변은 한국어로 작성한다."
        ),
        (
            "human",
            "AWS WAF 로그 분석 결과를 한 문장으로 요약해줘. 전체 요청 수는 {total_requests}건이다."
        )
    ])

    chain = prompt | llm | StrOutputParser()

    result = chain.invoke({
        "total_requests": 25
    })

    print(result)


if __name__ == "__main__":
    main()