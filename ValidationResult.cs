namespace Security.Jwt;

public record ValidationResult<T>
{
    public T Result { get; init; }
    public bool IsValid { get; init; }
}