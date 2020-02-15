using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class CorruptedDataException : Exception
    {
        internal CorruptedDataException()
        {
        }

        internal CorruptedDataException(string message) : base(message)
        {
        }

        internal CorruptedDataException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected CorruptedDataException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}