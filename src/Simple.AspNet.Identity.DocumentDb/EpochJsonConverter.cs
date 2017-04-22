using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Simple.AspNet.Identity.DocumentDb
{
    public class EpochJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(DateTime) || objectType == typeof(DateTimeOffset);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.None || reader.TokenType == JsonToken.Null)
                return Activator.CreateInstance(objectType);

            if (reader.TokenType != JsonToken.Integer)
            {
                throw new InvalidCastException($"Unexpected token parsing date. Expected Integer, got {reader.TokenType}");
            }

            var seconds = (long)reader.Value;
            var retVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds);
            if (objectType == typeof(DateTime))
                return retVal;
            else
                return new DateTimeOffset(retVal, TimeSpan.FromTicks(0));
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            int seconds;

            if (value != null && (value is DateTime || value is DateTimeOffset))
            {
                DateTime dt = value is DateTimeOffset ? ((DateTimeOffset)value).UtcDateTime : (DateTime)value;
                seconds = dt.ToEpoch();
            }
            else
            {
                throw new InvalidCastException($"Expected date object value {value?.GetType()}");
            }

            writer.WriteValue(seconds);
        }
    }
}
