using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class DataAlreadyExistsException : Exception
    {
        public DataAlreadyExistsException()
        {
        }

        public DataAlreadyExistsException(string message) : base(message)
        {
        }

        public DataAlreadyExistsException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected DataAlreadyExistsException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}